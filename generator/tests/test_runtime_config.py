import importlib
import sys
from pathlib import Path

import pytest
from kubernetes import config

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def generator(monkeypatch):
    monkeypatch.setenv("GENERATOR_SERVICE_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("CONTROLLER_MODE", "all")
    monkeypatch.setenv("WORKSPACE_ROOT", "/home/coder/project")
    monkeypatch.setattr(config, "load_incluster_config", lambda: None)
    module = importlib.import_module("main")
    return importlib.reload(module)


def test_image_pull_secret_names_support_legacy_and_csv(generator, monkeypatch):
    monkeypatch.setenv("IMAGE_PULL_SECRET_NAMES", "harbor-a, harbor-b")
    monkeypatch.setenv("IMAGE_PULL_SECRET_NAME", "harbor-a")

    assert generator.get_image_pull_secret_names() == ["harbor-a", "harbor-b"]


def test_code_server_args_are_shell_split(generator, monkeypatch):
    monkeypatch.setenv(
        "CODE_SERVER_ARGS",
        '--bind-addr 0.0.0.0:8080 --app-name "JCode IDE" /home/coder/project',
    )

    assert generator.get_code_server_args(False) == [
        "--bind-addr",
        "0.0.0.0:8080",
        "--app-name",
        "JCode IDE",
        "/home/coder/project",
        "--auth",
        "none",
        "--restrict-workspace-root",
        "/home/coder/project",
    ]


def test_workspace_images_must_use_immutable_harbor_reference(generator, monkeypatch):
    monkeypatch.setenv("WORKSPACE_INIT_IMAGE", "busybox:latest")
    with pytest.raises(RuntimeError, match="harbor.jbnu.ac.kr"):
        generator.get_workspace_init_image()

    monkeypatch.setenv(
        "WORKSPACE_INIT_IMAGE",
        "harbor.jbnu.ac.kr/jdevops/workspace-init@sha256:" + "a" * 64,
    )
    assert generator.get_workspace_init_image().startswith("harbor.jbnu.ac.kr/")


def test_workspace_root_rejects_prefix_collision(generator, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", "/home/coder/project-escape")

    with pytest.raises(RuntimeError):
        generator.get_workspace_root()


def test_nfs_mount_requires_workspace_directory(generator, monkeypatch, tmp_path):
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))

    with pytest.raises(RuntimeError, match="workspace 경로"):
        generator.validate_nfs_mount()

    (tmp_path / "workspace").mkdir()
    generator.validate_nfs_mount()


def test_wait_for_external_secret_uses_ready_condition(generator, monkeypatch):
    monkeypatch.setenv("IMAGE_PULL_SECRET_NAMES", "harbor-jcode-pull")

    class CustomObjects:
        def get_namespaced_custom_object(self, **kwargs):
            return {"status": {"conditions": [{"type": "Ready", "status": "True"}]}}

    generator.wait_for_external_image_pull_secrets(CustomObjects(), "jcode-course-1")


def test_wait_for_external_secret_fails_when_not_configured(generator, monkeypatch):
    monkeypatch.delenv("IMAGE_PULL_SECRET_NAMES", raising=False)
    monkeypatch.delenv("IMAGE_PULL_SECRET_NAME", raising=False)

    with pytest.raises(RuntimeError):
        generator.wait_for_external_image_pull_secrets(object(), "jcode-course-1")


def test_external_secret_is_created_without_reading_secret_material(generator, monkeypatch):
    monkeypatch.setenv("IMAGE_PULL_SECRET_NAMES", "harbor-jcode-pull")
    monkeypatch.setenv("IMAGE_PULL_SECRET_REMOTE_NAMES", "watcher-harbor-registry-secret")
    monkeypatch.setattr(generator, "EXTERNAL_SECRET_STORE_NAME", "jcode-harbor-pull-secret")

    class CustomObjects:
        def __init__(self):
            self.created = None

        def get_namespaced_custom_object(self, **kwargs):
            raise generator.ApiException(status=404)

        def create_namespaced_custom_object(self, **kwargs):
            self.created = kwargs["body"]

    custom_objects = CustomObjects()
    generator.ensure_external_image_pull_secrets(custom_objects, "jcode-course-1")

    assert custom_objects.created["spec"]["target"]["name"] == "harbor-jcode-pull"
    assert custom_objects.created["spec"]["dataFrom"][0]["extract"]["key"] == "watcher-harbor-registry-secret"
    assert "data" not in custom_objects.created


def test_workspace_proxy_environment_contains_upper_and_lowercase(generator, monkeypatch):
    monkeypatch.setattr(generator, "WORKSPACE_PROXY_URL", "http://proxy.watcher.svc:3000")

    values = {item.name: item.value for item in generator.get_workspace_proxy_env()}

    assert values["HTTP_PROXY"] == "http://proxy.watcher.svc:3000"
    assert values["https_proxy"] == "http://proxy.watcher.svc:3000"
    assert ".svc" in values["NO_PROXY"]


def test_watcher_hook_config_is_created_and_contains_dynamic_assignment_lookup(generator):
    class CoreV1:
        def __init__(self):
            self.created = None

        def read_namespaced_config_map(self, name, namespace):
            raise generator.ApiException(status=404)

        def create_namespaced_config_map(self, namespace, body):
            self.created = body

    core_v1 = CoreV1()
    generator.ensure_watcher_hook_config(core_v1, "jcode-course-1")

    assert core_v1.created.metadata.name == "watcher-hook-config"
    hook = core_v1.created.data["99-watcher-hook.py"]
    assert "relative_to(WORKSPACE_ROOT)" in hook
    assert "post_with_retry" in hook


def test_managed_config_map_is_replaced_with_resource_version(generator):
    class CoreV1:
        def __init__(self):
            self.replaced = None

        def read_namespaced_config_map(self, name, namespace):
            return generator.client.V1ConfigMap(
                metadata=generator.client.V1ObjectMeta(
                    name=name,
                    namespace=namespace,
                    resource_version="17",
                ),
                data={"old": "value"},
            )

        def replace_namespaced_config_map(self, name, namespace, body):
            self.replaced = body

    core_v1 = CoreV1()
    generator.ensure_code_server_config(core_v1, "jcode-course-1")

    assert core_v1.replaced.metadata.resource_version == "17"
    assert "config.yaml" in core_v1.replaced.data
