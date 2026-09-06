import asyncio
import json
import os
from types import SimpleNamespace

import pytest


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
        "--extensions-dir",
        "/home/coder/extensions",
        "--disable-workspace-trust",
        "--disable-telemetry",
        "--disable-update-check",
    ]


def test_removed_fork_workspace_flag_is_rejected(generator, monkeypatch):
    monkeypatch.setenv(
        "CODE_SERVER_ARGS",
        "--restrict-workspace-root /home/coder/project /home/coder/project",
    )

    with pytest.raises(RuntimeError, match="지원하지 않습니다"):
        generator.get_code_server_args(False)


def test_workspace_persists_only_extensions_and_has_readiness_probe(generator, monkeypatch):
    class AppsV1:
        def __init__(self):
            self.deployment = None

        def create_namespaced_deployment(self, namespace, body):
            self.deployment = body

    monkeypatch.setattr(generator, "get_requested_workspace_image", lambda *_: "harbor/image@sha256:" + "a" * 64)
    monkeypatch.setattr(generator, "get_workspace_init_image", lambda: "harbor/init@sha256:" + "b" * 64)
    monkeypatch.setattr(generator, "get_workspace_resources", lambda *_: generator.client.V1ResourceRequirements())
    monkeypatch.setattr(generator, "get_image_pull_secret_names", lambda: [])
    apps = AppsV1()

    generator.create_deployment(
        apps,
        "jcode-alg-1",
        "jcode-alg-1-20260001",
        "jcode-alg-1-20260001",
        "workspace/alg-1-20260001",
        "20260001",
        False,
        False,
    )

    pod_spec = apps.deployment.spec.template.spec
    init_mounts = pod_spec.init_containers[0].volume_mounts
    runtime = pod_spec.containers[0]
    assert all(mount.mount_path != "/home/coder/extensions" for mount in init_mounts)
    assert any(mount.mount_path == "/home/coder/extensions" for mount in runtime.volume_mounts)
    extension_mount = next(mount for mount in runtime.volume_mounts if mount.mount_path == "/home/coder/extensions")
    assert extension_mount.sub_path == "extensions-v2/20260001"
    assert extension_mount.read_only is True
    policy_mount = next(mount for mount in runtime.volume_mounts if mount.mount_path == "/etc/vscode/policy.json")
    assert policy_mount.sub_path == "policy.json"
    assert policy_mount.read_only is True
    assert next(item.value for item in runtime.env if item.name == "EXTENSIONS_GALLERY") == "{}"
    assert all(mount.mount_path != "/home/coder/.local" for mount in init_mounts + runtime.volume_mounts)
    assert "/home/coder/.local" not in " ".join(pod_spec.init_containers[0].command)
    assert "/home/coder/extensions" not in " ".join(pod_spec.init_containers[0].command)
    init_command = " ".join(pod_spec.init_containers[0].command)
    assert "/home/coder/project/workspace" in init_command
    assert "/home/coder/project/hw" not in init_command
    assert "/home/coder/project/prac" not in init_command
    assert runtime.readiness_probe.tcp_socket.port == 8080
    assert apps.deployment.spec.progress_deadline_seconds == 600


def test_existing_workspace_deployment_is_reconciled(generator, monkeypatch):
    class AppsV1:
        def __init__(self):
            self.patched = None

        def create_namespaced_deployment(self, namespace, body):
            raise generator.ApiException(status=409)

        def patch_namespaced_deployment(self, name, namespace, body):
            self.patched = body

    monkeypatch.setattr(generator, "get_requested_workspace_image", lambda *_: "harbor/image@sha256:" + "a" * 64)
    monkeypatch.setattr(generator, "get_workspace_init_image", lambda: "harbor/init@sha256:" + "b" * 64)
    monkeypatch.setattr(generator, "get_workspace_resources", lambda *_: generator.client.V1ResourceRequirements())
    monkeypatch.setattr(generator, "get_image_pull_secret_names", lambda: [])
    apps = AppsV1()

    result = generator.create_deployment(
        apps,
        "jcode-alg-1",
        "jcode-alg-1-20260001",
        "jcode-alg-1-20260001",
        "workspace/alg-1-20260001",
        "20260001",
        False,
        False,
    )

    assert result == "Deployment 'jcode-alg-1-20260001' 갱신 완료"
    runtime = apps.patched.spec.template.spec.containers[0]
    assert next(item.value for item in runtime.env if item.name == "EXTENSIONS_GALLERY") == "{}"
    assert next(
        mount.read_only for mount in runtime.volume_mounts
        if mount.mount_path == "/etc/vscode/policy.json"
    ) is True


def test_jcode_status_requires_deployment_and_service_endpoint(generator, monkeypatch):
    deployment = SimpleNamespace(
        metadata=SimpleNamespace(generation=3),
        spec=SimpleNamespace(replicas=1),
        status=SimpleNamespace(
            conditions=[],
            observed_generation=3,
            updated_replicas=1,
            available_replicas=1,
            ready_replicas=1,
        ),
    )
    core = SimpleNamespace(
        read_namespaced_endpoints=lambda *_: SimpleNamespace(
            subsets=[SimpleNamespace(addresses=[SimpleNamespace(ip="10.0.0.1")])]
        )
    )
    apps = SimpleNamespace(read_namespaced_deployment=lambda *_: deployment)
    monkeypatch.setattr(generator.client, "CoreV1Api", lambda: core)
    monkeypatch.setattr(generator.client, "AppsV1Api", lambda: apps)
    monkeypatch.setattr(generator, "verify_course_namespace", lambda *_: None)

    result = asyncio.run(generator.get_jcode_status(
        1,
        "jcode-alg-1",
        "jcode-alg-1-20260001",
        "jcode-alg-1-20260001-svc",
        {},
    ))

    assert result["state"] == "READY"


def test_jcode_status_reports_progress_deadline_failure(generator, monkeypatch):
    deployment = SimpleNamespace(
        metadata=SimpleNamespace(generation=3),
        spec=SimpleNamespace(replicas=1),
        status=SimpleNamespace(
            conditions=[SimpleNamespace(
                type="Progressing",
                status="False",
                reason="ProgressDeadlineExceeded",
            )],
        ),
    )
    core = SimpleNamespace()
    apps = SimpleNamespace(read_namespaced_deployment=lambda *_: deployment)
    monkeypatch.setattr(generator.client, "CoreV1Api", lambda: core)
    monkeypatch.setattr(generator.client, "AppsV1Api", lambda: apps)
    monkeypatch.setattr(generator, "verify_course_namespace", lambda *_: None)

    result = asyncio.run(generator.get_jcode_status(
        1,
        "jcode-alg-1",
        "jcode-alg-1-20260001",
        "jcode-alg-1-20260001-svc",
        {},
    ))

    assert result == {"state": "FAILED", "reasonCode": "DEPLOYMENT_PROGRESS_DEADLINE"}


def test_workspace_images_must_use_immutable_harbor_reference(generator, monkeypatch):
    monkeypatch.setenv("WORKSPACE_INIT_IMAGE", "busybox:latest")
    with pytest.raises(RuntimeError, match="harbor.jedutools.io"):
        generator.get_workspace_init_image()

    monkeypatch.setenv(
        "WORKSPACE_INIT_IMAGE",
        "harbor.jedutools.io/jdevops/workspace-init@sha256:" + "a" * 64,
    )
    assert generator.get_workspace_init_image().startswith("harbor.jedutools.io/")


def test_workspace_images_follow_configured_harbor_registry(generator, monkeypatch):
    monkeypatch.setenv("HARBOR_REGISTRY", "registry.internal:5443")
    monkeypatch.setenv(
        "WORKSPACE_INIT_IMAGE",
        "registry.internal:5443/jdevops/workspace-init@sha256:" + "b" * 64,
    )

    assert generator.get_workspace_init_image().startswith("registry.internal:5443/")

    monkeypatch.setenv("HARBOR_REGISTRY", "https://registry.internal")
    with pytest.raises(RuntimeError, match="HARBOR_REGISTRY"):
        generator.get_workspace_init_image()


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


def test_smoke_workspace_paths_are_prepared_and_removed(generator, monkeypatch, tmp_path):
    (tmp_path / "workspace").mkdir()
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))
    monkeypatch.setattr(os, "chown", lambda *_: None)
    file_path = "workspace/release-smoke/jcode-release-123-smoke"
    student_num = "release-smoke-123"

    workspace_path, extension_path = generator.prepare_smoke_workspace(file_path, student_num)

    assert workspace_path.is_dir()
    assert extension_path.is_dir()

    generator.cleanup_smoke_workspace(file_path, student_num)

    assert not workspace_path.exists()
    assert not extension_path.exists()
    assert (tmp_path / "extensions-v2").is_dir()


def test_workspace_extensions_directory_is_a_safe_single_segment(generator, monkeypatch, tmp_path):
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))
    monkeypatch.setenv("WORKSPACE_EXTENSIONS_DIR", "../extensions")

    with pytest.raises(RuntimeError, match="WORKSPACE_EXTENSIONS_DIR"):
        generator.get_workspace_extensions_root()


def test_workspace_extension_is_prepared_lazily_for_existing_members(generator, monkeypatch, tmp_path):
    (tmp_path / "workspace").mkdir()
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))
    monkeypatch.setattr(os, "chown", lambda *_: None)

    path = generator.prepare_workspace_extension("20260001")

    assert path == tmp_path / "extensions-v2" / "20260001"
    assert path.is_dir()


def test_workspace_extension_rejects_invalid_student_number(generator, monkeypatch, tmp_path):
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))

    with pytest.raises(generator.HTTPException, match="student_num"):
        generator.get_workspace_extension_subpath("../escape")


@pytest.mark.parametrize(
    ("file_path", "student_num"),
    [
        ("workspace/real-course/student", "release-smoke-123"),
        ("workspace/release-smoke/jcode-release-123-smoke", "student-123"),
        ("../workspace/release-smoke/jcode-release-123-smoke", "release-smoke-123"),
    ],
)
def test_smoke_workspace_paths_reject_non_reserved_names(generator, monkeypatch, tmp_path, file_path, student_num):
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))

    with pytest.raises(generator.HTTPException, match="smoke"):
        generator.get_smoke_workspace_paths(file_path, student_num)


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


@pytest.mark.parametrize(
    ("use_vnc", "watcher_api_base"),
    [
        (False, "http://watcher-backend-service.dev.svc.cluster.local:3000"),
        (True, "http://watcher-backend-service.watcher.svc.cluster.local:3000"),
    ],
)
def test_workspace_receives_environment_watcher_api(generator, monkeypatch, use_vnc, watcher_api_base):
    monkeypatch.setenv("WATCHER_API_BASE", watcher_api_base + "/")

    values = {item.name: item.value for item in generator.get_code_server_extra_env(use_vnc)}

    assert values["WATCHER_API_BASE"] == watcher_api_base


def test_workspace_watcher_api_default_follows_dev_environment(generator, monkeypatch):
    monkeypatch.delenv("WATCHER_API_BASE", raising=False)
    monkeypatch.setenv("JCODE_ENVIRONMENT", "dev")

    values = {item.name: item.value for item in generator.get_code_server_extra_env(False)}

    assert values["WATCHER_API_BASE"] == "http://watcher-backend-service.dev.svc.cluster.local:3000"


def test_workspace_dns_peers_include_nodelocal_dns(generator, monkeypatch):
    monkeypatch.setenv(
        "WORKSPACE_DNS_CIDRS",
        "169.254.25.10/32, 10.96.0.10/32, 169.254.25.10/32",
    )

    peers = generator.build_workspace_dns_peers()

    assert peers[0].pod_selector.match_labels == {"k8s-app": "kube-dns"}
    assert [peer.ip_block.cidr for peer in peers[1:]] == [
        "169.254.25.10/32",
        "10.96.0.10/32",
    ]


@pytest.mark.parametrize("value", ["", "169.254.25.10", "not-a-cidr"])
def test_workspace_dns_cidrs_reject_missing_or_invalid_values(generator, monkeypatch, value):
    monkeypatch.setenv("WORKSPACE_DNS_CIDRS", value)

    with pytest.raises(RuntimeError, match="WORKSPACE_DNS_CIDRS"):
        generator.get_workspace_dns_cidrs()


@pytest.mark.parametrize("value", [None, "169.254.25.10", "not-a-cidr"])
def test_bootstrap_startup_rejects_missing_or_invalid_dns_cidrs(generator, monkeypatch, value):
    monkeypatch.setattr(generator, "CONTROLLER_MODE", "bootstrap")
    monkeypatch.setattr(generator, "EXTERNAL_SECRET_STORE_NAME", "jcode-harbor-pull-secret")
    monkeypatch.setenv("IMAGE_PULL_SECRET_NAMES", "watcher-harbor-registry-secret")
    if value is None:
        monkeypatch.delenv("WORKSPACE_DNS_CIDRS", raising=False)
    else:
        monkeypatch.setenv("WORKSPACE_DNS_CIDRS", value)

    with pytest.raises(RuntimeError, match="WORKSPACE_DNS_CIDRS"):
        generator.validate_on_startup()


def test_workspace_pod_uses_short_dns_search_threshold(generator):
    dns_config = generator.get_pod_dns_config()

    assert [(option.name, option.value) for option in dns_config.options] == [("ndots", "2")]


def test_workspace_scheduling_config_is_parsed(generator, monkeypatch):
    monkeypatch.setenv("WORKSPACE_NODE_SELECTOR", '{"env":"dev"}')
    monkeypatch.setenv(
        "WORKSPACE_TOLERATIONS",
        '[{"key":"dev-node","operator":"Equal","value":"true","effect":"NoSchedule"}]',
    )

    assert generator.get_workspace_node_selector() == {"env": "dev"}
    toleration = generator.get_workspace_tolerations()[0]
    assert toleration.key == "dev-node"
    assert toleration.effect == "NoSchedule"


def test_workspace_scheduling_config_rejects_invalid_json(generator, monkeypatch):
    monkeypatch.setenv("WORKSPACE_NODE_SELECTOR", "[]")

    with pytest.raises(RuntimeError, match="key/value"):
        generator.get_workspace_node_selector()


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
    assert '"AllowedExtensions"' in core_v1.replaced.data["policy.json"]
    assert '"*": false' in core_v1.replaced.data["policy.json"]
    policy = json.loads(core_v1.replaced.data["policy.json"])
    assert policy["ChatAgentMode"] is False
    assert policy["ChatMCP"] == "none"
    assert policy["ChatAllowedMcpServers"] == []
    assert policy["Claude3PIntegration"] is False
    assert policy["Codex3PIntegration"] is False
