import asyncio
import importlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from kubernetes import config

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def generator(monkeypatch):
    monkeypatch.setenv("GENERATOR_SERVICE_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("CONTROLLER_MODE", "bootstrap")
    monkeypatch.setattr(config, "load_incluster_config", lambda: None)
    module = importlib.import_module("main")
    return importlib.reload(module)


def token(generator, *, audience="jcode-generator", scope="jcode:write", subject="jcode-backend"):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": "jcode-backend",
            "aud": audience,
            "sub": subject,
            "iat": now,
            "exp": now + timedelta(seconds=60),
            "scope": scope,
            "namespace_prefix": "jcode-",
        },
        generator.SERVICE_SECRET,
        algorithm="HS256",
    )


def credentials(value):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=value)


@pytest.mark.parametrize("namespace", ["default", "watcher", "jcode-OS-1", "course-os-1", "jcode-os"])
def test_namespace_name_rejects_outside_or_invalid_values(generator, namespace):
    with pytest.raises(HTTPException):
        generator.validate_namespace(namespace)


def test_namespace_name_accepts_course_pattern(generator):
    generator.validate_namespace("jcode-os-1")


def test_dev_namespace_is_resolved_without_backend_contract_change(generator, monkeypatch):
    monkeypatch.setenv("JCODE_ENVIRONMENT", "dev")
    monkeypatch.setenv("COURSE_NAMESPACE_PREFIX", "jcode-dev-")
    dev_generator = importlib.reload(generator)

    assert dev_generator.resolve_namespace("jcode-os-1") == "jcode-dev-os-1"
    dev_generator.validate_namespace("jcode-dev-os-1")
    with pytest.raises(HTTPException):
        dev_generator.validate_namespace("jcode-os-1")


def test_service_token_requires_correct_audience(generator):
    dependency = generator.require_service_scope("jcode:write", "bootstrap")
    with pytest.raises(HTTPException) as error:
        dependency(credentials(token(generator, audience="browser")))
    assert error.value.status_code == 401


def test_service_token_requires_operation_scope(generator):
    dependency = generator.require_service_scope("namespace:delete", "bootstrap")
    with pytest.raises(HTTPException) as error:
        dependency(credentials(token(generator, scope="jcode:write")))
    assert error.value.status_code == 403


def test_course_namespace_metadata_must_match(generator):
    class CoreV1:
        def read_namespaced_config_map(self, name, namespace):
            return generator.client.V1ConfigMap(data={"course-id": "11", "namespace": namespace})

        def read_namespace(self, name):
            return generator.client.V1Namespace(
                metadata=generator.client.V1ObjectMeta(
                    labels={"jcode.io/environment": "prod"},
                    annotations={"jcode.io/environment": "prod"},
                )
            )

    generator.verify_course_namespace(CoreV1(), "jcode-os-1", 11)
    with pytest.raises(HTTPException) as error:
        generator.verify_course_namespace(CoreV1(), "jcode-os-1", 12)
    assert error.value.status_code == 403


def test_course_namespace_metadata_cannot_be_reassigned(generator):
    class CoreV1:
        def read_namespaced_config_map(self, name, namespace):
            return generator.client.V1ConfigMap(data={"course-id": "11", "namespace": namespace})

    with pytest.raises(HTTPException) as error:
        generator.ensure_course_metadata(CoreV1(), "jcode-os-1", 12)
    assert error.value.status_code == 409


def test_course_namespace_metadata_is_created_immutable(generator):
    class CoreV1:
        created = None

        def read_namespaced_config_map(self, name, namespace):
            raise generator.ApiException(status=404)

        def create_namespaced_config_map(self, namespace, body):
            self.created = body

    core = CoreV1()
    generator.ensure_course_metadata(core, "jcode-os-1", 11)

    assert core.created.immutable is True
    assert core.created.data == {
        "course-id": "11",
        "namespace": "jcode-os-1",
        "environment": "prod",
    }


def test_workspace_role_binding_is_fixed_to_runtime_cluster_role(generator):
    binding = generator.build_workspace_role_binding("jcode-os-1")

    assert binding.metadata.namespace == "jcode-os-1"
    assert binding.role_ref.kind == "ClusterRole"
    assert binding.metadata.name == "jcode-workspace-runtime-v2"
    assert binding.role_ref.name == "jcode-workspace-runtime-v2"
    assert [(item.kind, item.namespace, item.name) for item in binding.subjects] == [
        ("ServiceAccount", "watcher", "jcode-workspace-v2")
    ]


def test_existing_namespace_metadata_cannot_change_course(generator):
    class CoreV1:
        def read_namespace(self, name):
            return generator.client.V1Namespace(
                metadata=generator.client.V1ObjectMeta(
                    name=name,
                    annotations={"jcode.io/course-id": "11"},
                )
            )

    with pytest.raises(HTTPException) as error:
        generator.ensure_namespace_metadata(CoreV1(), "jcode-os-1", 12)

    assert error.value.status_code == 409


def test_namespace_resource_cleanup_does_not_delete_pods_directly(generator):
    class Apps:
        def list_namespaced_deployment(self, namespace):
            return type("Result", (), {"items": []})()

    class Core:
        def list_namespaced_service(self, namespace):
            return type("Result", (), {"items": []})()

        def delete_collection_namespaced_pod(self, namespace):
            raise AssertionError("pods must be garbage-collected through Deployment ownership")

    generator.delete_all_resources_in_namespace(Core(), Apps(), "jcode-os-1")


def test_namespace_delete_waits_for_not_found(generator, monkeypatch):
    class Core:
        calls = 0

        def read_namespace(self, name):
            self.calls += 1
            if self.calls == 2:
                raise generator.ApiException(status=404)

    monkeypatch.setattr(generator.time, "sleep", lambda _: None)

    assert generator.wait_for_namespace_deleted(Core(), "jcode-os-1", timeout_seconds=10)


def test_namespace_delete_timeout_keeps_operation_pending(generator):
    class Core:
        def read_namespace(self, name):
            return object()

    assert not generator.wait_for_namespace_deleted(Core(), "jcode-os-1", timeout_seconds=0)


def test_missing_namespace_is_confirmed_deleted(generator, monkeypatch):
    class Core:
        def read_namespace(self, name):
            raise generator.ApiException(status=404)

    monkeypatch.setattr(generator.client, "CoreV1Api", Core)

    response = asyncio.run(generator.delete_namespace_api("jcode-os-1", 11, {}))

    assert response["deleted"] is True
