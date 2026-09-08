#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
from dataclasses import dataclass
from typing import Any, Optional


WORKSPACE_ROLE_BINDING = "jcode-workspace-runtime-v2"
WORKSPACE_SERVICE_ACCOUNT = "jcode-workspace-v2"


@dataclass(frozen=True)
class Target:
    environment: str
    controller_namespace: str
    configmap_name: str
    namespace_prefix: str


class Kubectl:
    def get_json(
        self,
        resource: str,
        name: Optional[str] = None,
        *,
        namespace: Optional[str] = None,
        optional: bool = False,
    ) -> Optional[dict[str, Any]]:
        command = ["kubectl", "get", resource]
        if name:
            command.append(name)
        if namespace:
            command.extend(["-n", namespace])
        if optional:
            command.append("--ignore-not-found")
        command.extend(["-o", "json"])
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        if optional and not result.stdout.strip():
            return None
        return json.loads(result.stdout)

    def upsert_network_policy(self, namespace: str, policy: dict[str, Any]) -> None:
        existing = self.get_json(
            "networkpolicy",
            policy["metadata"]["name"],
            namespace=namespace,
            optional=True,
        )
        if existing is None:
            subprocess.run(
                ["kubectl", "create", "-f", "-"],
                input=json.dumps(policy),
                check=True,
                text=True,
            )
            return
        subprocess.run(
            [
                "kubectl",
                "patch",
                "networkpolicy",
                policy["metadata"]["name"],
                "-n",
                namespace,
                "--type=merge",
                "--patch",
                json.dumps({"spec": policy["spec"]}),
            ],
            check=True,
        )


def parse_dns_cidrs(value: str) -> list[str]:
    configured = [item.strip() for item in value.split(",") if item.strip()]
    if not configured:
        raise ValueError("WORKSPACE_DNS_CIDRS must contain at least one CIDR")
    cidrs = []
    for item in configured:
        if "/" not in item:
            raise ValueError(f"WORKSPACE_DNS_CIDRS contains an invalid CIDR: {item}")
        try:
            cidrs.append(str(ipaddress.ip_network(item, strict=True)))
        except ValueError as error:
            raise ValueError(f"WORKSPACE_DNS_CIDRS contains an invalid CIDR: {item}") from error
    return list(dict.fromkeys(cidrs))


def load_runtime_config(configmap: dict[str, Any]) -> dict[str, Any]:
    data = configmap.get("data") or {}
    required = (
        "WORKSPACE_DNS_CIDRS",
        "WATCHER_NAMESPACE",
        "WORKSPACE_PROXY_NAMESPACE",
        "WORKSPACE_PROXY_POD_LABEL",
        "WORKSPACE_PROXY_PORT",
    )
    missing = [name for name in required if not str(data.get(name, "")).strip()]
    if missing:
        raise ValueError(f"Generator ConfigMap is missing: {', '.join(missing)}")
    try:
        proxy_port = int(data["WORKSPACE_PROXY_PORT"])
    except ValueError as error:
        raise ValueError("WORKSPACE_PROXY_PORT must be an integer") from error
    if not 1 <= proxy_port <= 65535:
        raise ValueError("WORKSPACE_PROXY_PORT must be between 1 and 65535")
    return {
        "dns_cidrs": parse_dns_cidrs(data["WORKSPACE_DNS_CIDRS"]),
        "watcher_namespace": data["WATCHER_NAMESPACE"].strip(),
        "proxy_namespace": data["WORKSPACE_PROXY_NAMESPACE"].strip(),
        "proxy_label": data["WORKSPACE_PROXY_POD_LABEL"].strip(),
        "proxy_port": proxy_port,
    }


def build_workspace_egress(namespace: str, runtime: dict[str, Any]) -> dict[str, Any]:
    dns_peers = [
        {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
            },
            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
        }
    ]
    dns_peers.extend({"ipBlock": {"cidr": cidr}} for cidr in runtime["dns_cidrs"])
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "workspace-egress", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"jcode/component": "workspace"}},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": dns_peers,
                    "ports": [
                        {"port": 53, "protocol": "UDP"},
                        {"port": 53, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": runtime["watcher_namespace"]
                                }
                            },
                            "podSelector": {"matchLabels": {"app": "watcher-backend"}},
                        }
                    ],
                    "ports": [{"port": 3000, "protocol": "TCP"}],
                },
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": runtime["proxy_namespace"]
                                }
                            },
                            "podSelector": {
                                "matchLabels": {"app": runtime["proxy_label"]}
                            },
                        }
                    ],
                    "ports": [{"port": runtime["proxy_port"], "protocol": "TCP"}],
                },
            ],
        },
    }


def is_managed_v2_namespace(
    kubectl: Kubectl,
    target: Target,
    namespace: str,
) -> bool:
    if not namespace.startswith(target.namespace_prefix):
        return False
    metadata = kubectl.get_json(
        "configmap",
        "jcode-course-metadata",
        namespace=namespace,
        optional=True,
    )
    if metadata is None:
        return False
    data = metadata.get("data") or {}
    if data.get("environment") != target.environment or data.get("namespace") != namespace:
        return False
    if not str(data.get("course-id", "")).isdigit() or int(data["course-id"]) <= 0:
        return False
    binding = kubectl.get_json(
        "rolebinding",
        WORKSPACE_ROLE_BINDING,
        namespace=namespace,
        optional=True,
    )
    if binding is None:
        return False
    role_ref = binding.get("roleRef") or {}
    if role_ref.get("kind") != "ClusterRole" or role_ref.get("name") != WORKSPACE_ROLE_BINDING:
        return False
    return any(
        subject.get("kind") == "ServiceAccount"
        and subject.get("namespace") == target.controller_namespace
        and subject.get("name") == WORKSPACE_SERVICE_ACCOUNT
        for subject in binding.get("subjects") or []
    )


def reconcile(kubectl: Kubectl, target: Target) -> list[str]:
    configmap = kubectl.get_json(
        "configmap",
        target.configmap_name,
        namespace=target.controller_namespace,
    )
    if configmap is None:
        raise RuntimeError(f"Generator ConfigMap not found: {target.configmap_name}")
    runtime = load_runtime_config(configmap)
    namespaces = kubectl.get_json("namespaces") or {"items": []}
    updated = []
    for item in namespaces.get("items") or []:
        namespace = ((item.get("metadata") or {}).get("name") or "").strip()
        if not namespace or not is_managed_v2_namespace(kubectl, target, namespace):
            continue
        kubectl.upsert_network_policy(namespace, build_workspace_egress(namespace, runtime))
        updated.append(namespace)
        print(f"updated workspace-egress: {namespace}")
    print(f"workspace DNS reconciliation complete: {len(updated)} namespace(s)")
    return updated


def parse_target(value: str, namespace: Optional[str], configmap: Optional[str]) -> Target:
    if value == "dev":
        return Target("dev", namespace or "dev", configmap or "jcode-generator-dev-configmap", "jcode-dev-")
    if value in {"prod", "production"}:
        return Target("prod", namespace or "watcher", configmap or "jcode-generator-configmap", "jcode-")
    raise ValueError(f"target must be dev, prod, or production: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconcile Workspace DNS NetworkPolicy")
    parser.add_argument("target", choices=("dev", "prod", "production"))
    parser.add_argument("--namespace")
    parser.add_argument("--configmap")
    args = parser.parse_args()
    reconcile(Kubectl(), parse_target(args.target, args.namespace, args.configmap))


if __name__ == "__main__":
    main()
