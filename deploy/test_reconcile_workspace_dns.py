import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("reconcile_workspace_dns.py")
SPEC = importlib.util.spec_from_file_location("reconcile_workspace_dns", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def metadata(namespace, environment="dev", course_id="1"):
    return {
        "data": {
            "course-id": course_id,
            "namespace": namespace,
            "environment": environment,
        }
    }


def binding(namespace="dev"):
    return {
        "roleRef": {"kind": "ClusterRole", "name": "jcode-workspace-runtime-v2"},
        "subjects": [
            {
                "kind": "ServiceAccount",
                "namespace": namespace,
                "name": "jcode-workspace-v2",
            }
        ],
    }


class FakeKubectl:
    def __init__(self):
        self.updated = []
        self.resources = {
            ("configmap", "jcode-generator-dev-configmap", "dev"): {
                "data": {
                    "WORKSPACE_DNS_CIDRS": "169.254.25.10/32,10.96.0.10/32",
                    "WATCHER_NAMESPACE": "dev",
                    "WORKSPACE_PROXY_NAMESPACE": "dev",
                    "WORKSPACE_PROXY_POD_LABEL": "jcode-router",
                    "WORKSPACE_PROXY_PORT": "3000",
                }
            },
            ("configmap", "jcode-course-metadata", "jcode-dev-active-1"): metadata(
                "jcode-dev-active-1"
            ),
            ("rolebinding", "jcode-workspace-runtime-v2", "jcode-dev-active-1"): binding(),
            ("configmap", "jcode-course-metadata", "jcode-dev-prod-1"): metadata(
                "jcode-dev-prod-1", environment="prod"
            ),
            ("rolebinding", "jcode-workspace-runtime-v2", "jcode-dev-prod-1"): binding(),
            ("configmap", "jcode-course-metadata", "jcode-dev-legacy-1"): metadata(
                "jcode-dev-legacy-1"
            ),
        }

    def get_json(self, resource, name=None, *, namespace=None, optional=False):
        if resource == "namespaces":
            return {
                "items": [
                    {"metadata": {"name": "jcode-dev-active-1"}},
                    {"metadata": {"name": "jcode-dev-prod-1"}},
                    {"metadata": {"name": "jcode-dev-legacy-1"}},
                    {"metadata": {"name": "jcode-dev-no-metadata-1"}},
                    {"metadata": {"name": "jcode-unmanaged-1"}},
                ]
            }
        value = self.resources.get((resource, name, namespace))
        if value is None and not optional:
            raise AssertionError(f"missing fixture: {resource}/{name} in {namespace}")
        return value

    def upsert_network_policy(self, namespace, policy):
        self.updated.append((namespace, policy))


class ReconcileWorkspaceDnsTest(unittest.TestCase):
    def test_only_matching_v2_namespace_is_updated(self):
        kubectl = FakeKubectl()
        target = MODULE.parse_target("dev", None, None)

        updated = MODULE.reconcile(kubectl, target)

        self.assertEqual(updated, ["jcode-dev-active-1"])
        namespace, policy = kubectl.updated[0]
        self.assertEqual(namespace, "jcode-dev-active-1")
        peers = policy["spec"]["egress"][0]["to"]
        self.assertEqual(
            [peer["ipBlock"]["cidr"] for peer in peers if "ipBlock" in peer],
            ["169.254.25.10/32", "10.96.0.10/32"],
        )
        self.assertEqual(
            policy["spec"]["egress"][1]["to"][0]["namespaceSelector"]["matchLabels"],
            {"kubernetes.io/metadata.name": "dev"},
        )

    def test_invalid_dns_cidr_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "WORKSPACE_DNS_CIDRS"):
            MODULE.parse_dns_cidrs("169.254.25.10")


if __name__ == "__main__":
    unittest.main()
