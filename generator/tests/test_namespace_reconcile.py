import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import namespace_reconcile
from namespace_reconcile import Course, reconcile, summarize_findings


def healthy_inventory(course_id="11"):
    return {
        "jcode-os-1": {
            "label_course_id": course_id,
            "annotation_course_id": course_id,
            "config_course_id": course_id,
            "binding": {
                "role_kind": "ClusterRole",
                "role_name": "jcode-workspace-runtime-v2",
                "subjects": [
                    {"kind": "ServiceAccount", "name": "jcode-workspace-v2", "namespace": "watcher"}
                ],
            },
            "label_environment": "prod",
            "annotation_environment": "prod",
            "migration_state": None,
            "legacy_bindings": [],
            "missing_secrets": [],
        }
    }


def test_reconcile_reports_no_drift_for_expected_namespace():
    findings = reconcile([Course(11, "OS", 1)], healthy_inventory(), "watcher")

    assert all(not items for items in findings.values())


def test_reconcile_uses_isolated_dev_namespace():
    inventory = healthy_inventory()
    inventory["jcode-dev-os-1"] = inventory.pop("jcode-os-1")
    inventory["jcode-dev-os-1"]["label_environment"] = "dev"
    inventory["jcode-dev-os-1"]["annotation_environment"] = "dev"
    inventory["jcode-dev-os-1"]["binding"]["subjects"][0]["namespace"] = "dev"

    findings = reconcile([Course(11, "OS", 1)], inventory, "dev", "dev")

    assert all(not items for items in findings.values())


def test_reconcile_reports_legacy_dev_binding_outside_dev_prefix():
    inventory = healthy_inventory()
    inventory["jcode-os-1"]["legacy_bindings"] = [
        {
            "name": "deployment-manager-binding",
            "subjects": [
                {"kind": "ServiceAccount", "name": "jcode-generator-dev", "namespace": "dev"}
            ],
        }
    ]

    findings = reconcile([Course(11, "OS", 1)], inventory, "dev", "dev")

    assert findings["legacy_rolebinding"][0]["namespace"] == "jcode-os-1"
    assert findings["missing_namespace"][0]["namespace"] == "jcode-dev-os-1"


def test_reconcile_reports_quarantined_legacy_namespace_separately():
    inventory = healthy_inventory()
    inventory["jcode-os-1"]["migration_state"] = "quarantined"
    inventory["jcode-os-1"]["legacy_bindings"] = []

    findings = reconcile([], inventory, "dev", "dev")

    assert findings["quarantined_namespace"] == [{"namespace": "jcode-os-1"}]
    assert findings["orphan"] == []

    drift_count, drift, information = summarize_findings(findings)
    assert drift_count == 0
    assert "quarantined_namespace" not in drift
    assert information == {"quarantined_namespace": [{"namespace": "jcode-os-1"}]}


def test_fail_on_drift_ignores_quarantined_namespace(monkeypatch, capsys):
    inventory = healthy_inventory()
    inventory["jcode-os-1"]["migration_state"] = "quarantined"
    monkeypatch.setattr(sys, "argv", [
        "namespace_reconcile.py",
        "--courses-file", "courses.json",
        "--environment", "dev",
        "--controller-namespace", "dev",
        "--fail-on-drift",
    ])
    monkeypatch.setattr(namespace_reconcile, "load_courses_from_file", lambda _: [])
    monkeypatch.setattr(namespace_reconcile, "load_kubernetes_config", lambda: None)
    monkeypatch.setattr(namespace_reconcile, "collect_cluster_inventory", lambda *_: inventory)

    assert namespace_reconcile.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["drift_count"] == 0
    assert output["information"]["quarantined_namespace"] == [{"namespace": "jcode-os-1"}]


def test_reconcile_classifies_namespace_drift():
    inventory = healthy_inventory(course_id="99")
    inventory["jcode-orphan-1"] = inventory["jcode-os-1"]
    inventory["jcode-os-1"]["binding"] = None
    inventory["jcode-os-1"]["missing_secrets"] = ["watcher-harbor-registry-secret"]
    inventory["jcode-os-1"]["legacy_bindings"] = [{"name": "deployment-manager-binding"}]

    findings = reconcile([Course(11, "OS", 1), Course(12, "DB", 1)], inventory, "watcher")

    assert findings["orphan"][0]["namespace"] == "jcode-orphan-1"
    assert findings["missing_namespace"][0]["namespace"] == "jcode-db-1"
    assert findings["metadata_mismatch"][0]["namespace"] == "jcode-os-1"
    assert findings["rolebinding_missing"][0]["namespace"] == "jcode-os-1"
    assert findings["legacy_rolebinding"][0]["namespace"] == "jcode-os-1"
    assert findings["harbor_secret_missing"][0]["namespace"] == "jcode-os-1"
