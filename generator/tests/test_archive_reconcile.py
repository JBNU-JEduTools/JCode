import importlib.util
import json
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / "archive_reconcile.py"
    spec = importlib.util.spec_from_file_location("archive_reconcile", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_expired_valid_archives_are_selected(tmp_path):
    module = load_module()
    expired = tmp_path / "expired"
    active = tmp_path / "active"
    invalid = tmp_path / "invalid"
    for path in (expired, active, invalid):
        path.mkdir()
    (expired / ".retention.json").write_text(
        json.dumps({"archived_at": 100, "retention_days": 1}), encoding="utf-8"
    )
    (active / ".retention.json").write_text(
        json.dumps({"archived_at": 100, "retention_days": 10}), encoding="utf-8"
    )
    (invalid / ".retention.json").write_text("{}", encoding="utf-8")

    assert list(module.expired_archives(tmp_path, 100 + 2 * 86400)) == [expired.resolve()]
