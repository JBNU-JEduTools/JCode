import importlib
import sys
from pathlib import Path

import pytest
from kubernetes import config


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def generator(monkeypatch):
    monkeypatch.setenv("GENERATOR_SERVICE_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("CONTROLLER_MODE", "workspace")
    monkeypatch.setenv("WORKSPACE_ROOT", "/home/coder/project")
    monkeypatch.setattr(config, "load_incluster_config", lambda: None)
    module = importlib.import_module("main")
    return importlib.reload(module)
