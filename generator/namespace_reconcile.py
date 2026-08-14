#!/usr/bin/env python3
"""DB 강의와 Kubernetes namespace 상태를 비교하는 읽기 전용 점검 도구."""

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlparse

from kubernetes import client, config
from kubernetes.client.rest import ApiException


@dataclass(frozen=True)
class Course:
    course_id: int
    code: str
    clss: int

    @property
    def namespace(self) -> str:
        return f"jcode-{self.code.lower()}-{self.clss}"


def load_courses_from_file(path: Path) -> list[Course]:
    values = json.loads(path.read_text(encoding="utf-8"))
    return [Course(int(item["id"]), str(item["code"]), int(item["clss"])) for item in values]


def load_courses_from_db(database_url: str) -> list[Course]:
    import pymysql

    parsed = urlparse(database_url)
    if parsed.scheme not in {"mysql", "mariadb"} or not parsed.hostname or not parsed.path.strip("/"):
        raise ValueError("database URL은 mysql://user:password@host:3306/database 형식이어야 합니다.")
    connection = pymysql.connect(
        host=parsed.hostname,
        port=parsed.port or 3306,
        user=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        database=unquote(parsed.path.lstrip("/")),
        connect_timeout=10,
        read_timeout=30,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, code, clss FROM course WHERE status <> 'ARCHIVED'")
            return [Course(int(row["id"]), str(row["code"]), int(row["clss"])) for row in cursor]
    finally:
        connection.close()


def load_kubernetes_config() -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def collect_cluster_inventory(
    secret_names: Iterable[str],
    namespace_prefix: str = "jcode-",
    environment: str = "prod",
) -> dict[str, dict]:
    core = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()
    inventory = {}
    for namespace in core.list_namespace().items:
        name = namespace.metadata.name
        annotations = namespace.metadata.annotations or {}
        labels = namespace.metadata.labels or {}
        namespace_bindings = None
        if not name.startswith(namespace_prefix):
            if environment != "dev" or not name.startswith("jcode-"):
                continue
            namespace_bindings = rbac.list_namespaced_role_binding(name)
            has_legacy_dev_binding = any(
                item.kind == "ServiceAccount"
                and item.namespace == "dev"
                and item.name == "jcode-generator-dev"
                for binding in namespace_bindings.items
                for item in (binding.subjects or [])
            )
            if not has_legacy_dev_binding and labels.get("jcode.io/migration-state") != "quarantined":
                continue
        if environment == "prod" and name.startswith("jcode-dev-"):
            continue
        config_course_id = None
        try:
            metadata = core.read_namespaced_config_map("jcode-course-metadata", name)
            config_course_id = (metadata.data or {}).get("course-id")
        except ApiException as error:
            if error.status != 404:
                raise
        legacy_bindings = []
        namespace_bindings = namespace_bindings or rbac.list_namespaced_role_binding(name)
        for legacy in namespace_bindings.items:
            if legacy.metadata.name == "jcode-workspace-runtime-v2":
                continue
            subjects = [
                {"kind": item.kind, "name": item.name, "namespace": item.namespace}
                for item in (legacy.subjects or [])
            ]
            if any(
                item["kind"] == "ServiceAccount"
                and item["name"] in {"jcode-workspace", "jcode-generator-dev"}
                for item in subjects
            ):
                legacy_bindings.append({"name": legacy.metadata.name, "subjects": subjects})
        binding = None
        try:
            binding = rbac.read_namespaced_role_binding("jcode-workspace-runtime-v2", name)
        except ApiException as error:
            if error.status != 404:
                raise
        missing_secrets = []
        for secret_name in secret_names:
            try:
                core.read_namespaced_secret(secret_name, name)
            except ApiException as error:
                if error.status == 404:
                    missing_secrets.append(secret_name)
                else:
                    raise
        inventory[name] = {
            "label_course_id": labels.get("jcode.io/course-id"),
            "annotation_course_id": annotations.get("jcode.io/course-id"),
            "label_environment": labels.get("jcode.io/environment"),
            "annotation_environment": annotations.get("jcode.io/environment"),
            "migration_state": labels.get("jcode.io/migration-state"),
            "config_course_id": config_course_id,
            "binding": None if binding is None else {
                "role_kind": binding.role_ref.kind,
                "role_name": binding.role_ref.name,
                "subjects": [
                    {"kind": item.kind, "name": item.name, "namespace": item.namespace}
                    for item in (binding.subjects or [])
                ],
            },
            "legacy_bindings": legacy_bindings,
            "missing_secrets": missing_secrets,
        }
    return inventory


def reconcile(
    courses: Iterable[Course],
    inventory: dict[str, dict],
    controller_namespace: str,
    environment: str = "prod",
) -> dict:
    namespace_prefix = "jcode-dev-" if environment == "dev" else "jcode-"
    expected = {
        f"{namespace_prefix}{course.code.lower()}-{course.clss}": course
        for course in courses
    }
    result = {
        "missing_namespace": [],
        "orphan": [],
        "metadata_missing": [],
        "metadata_mismatch": [],
        "rolebinding_missing": [],
        "rolebinding_invalid": [],
        "legacy_rolebinding": [],
        "quarantined_namespace": [],
        "harbor_secret_missing": [],
    }
    for name, course in expected.items():
        if name not in inventory:
            result["missing_namespace"].append({"namespace": name, "course_id": course.course_id})
    for name, state in inventory.items():
        if state.get("migration_state") == "quarantined":
            result["quarantined_namespace"].append({"namespace": name})
        if state.get("legacy_bindings"):
            result["legacy_rolebinding"].append(
                {"namespace": name, "bindings": state["legacy_bindings"]}
            )
        course = expected.get(name)
        if course is None:
            if state.get("migration_state") != "quarantined":
                result["orphan"].append({"namespace": name})
            continue
        expected_id = str(course.course_id)
        metadata_values = [
            state.get("label_course_id"),
            state.get("annotation_course_id"),
            state.get("config_course_id"),
        ]
        environment_values = [state.get("label_environment"), state.get("annotation_environment")]
        if any(value is None for value in metadata_values + environment_values):
            result["metadata_missing"].append({"namespace": name, "values": metadata_values})
        elif any(str(value) != expected_id for value in metadata_values) or any(
            value != environment for value in environment_values
        ):
            result["metadata_mismatch"].append(
                {"namespace": name, "course_id": course.course_id, "values": metadata_values}
            )
        binding = state.get("binding")
        expected_subject = {
            "kind": "ServiceAccount",
            "name": "jcode-workspace-v2",
            "namespace": controller_namespace,
        }
        if binding is None:
            result["rolebinding_missing"].append({"namespace": name})
        elif (
            binding.get("role_kind") != "ClusterRole"
            or binding.get("role_name") != "jcode-workspace-runtime-v2"
            or binding.get("subjects") != [expected_subject]
        ):
            result["rolebinding_invalid"].append({"namespace": name, "binding": binding})
        if state.get("missing_secrets"):
            result["harbor_secret_missing"].append(
                {"namespace": name, "secrets": state["missing_secrets"]}
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="JCode namespace 상태를 변경 없이 비교합니다.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--database-url", default=os.getenv("JCODE_DATABASE_URL"))
    source.add_argument("--courses-file", type=Path)
    parser.add_argument("--controller-namespace", default=os.getenv("POD_NAMESPACE", "watcher"))
    parser.add_argument("--environment", choices=["dev", "prod"], default=os.getenv("JCODE_ENVIRONMENT", "prod"))
    parser.add_argument(
        "--harbor-secret",
        action="append",
        default=["watcher-harbor-registry-secret"],
        help="필수 Harbor Secret 이름. 여러 번 지정할 수 있습니다.",
    )
    parser.add_argument("--fail-on-drift", action="store_true")
    args = parser.parse_args()
    if bool(args.database_url) == bool(args.courses_file):
        parser.error("--database-url 또는 --courses-file 중 하나만 지정해야 합니다.")

    courses = (
        load_courses_from_file(args.courses_file)
        if args.courses_file
        else load_courses_from_db(args.database_url)
    )
    load_kubernetes_config()
    namespace_prefix = "jcode-dev-" if args.environment == "dev" else "jcode-"
    result = reconcile(
        courses,
        collect_cluster_inventory(args.harbor_secret, namespace_prefix, args.environment),
        args.controller_namespace,
        args.environment,
    )
    drift_count = sum(len(items) for items in result.values())
    print(json.dumps({"dry_run": True, "drift_count": drift_count, "findings": result}, ensure_ascii=False, indent=2))
    return 2 if args.fail_on_drift and drift_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
