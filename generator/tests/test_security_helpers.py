import importlib
import io
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from kubernetes import config

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def generator(monkeypatch):
    monkeypatch.setenv("GENERATOR_SERVICE_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("CONTROLLER_MODE", "workspace")
    monkeypatch.setattr(config, "load_incluster_config", lambda: None)
    module = importlib.import_module("main")
    return importlib.reload(module)


def test_validate_workspace_dir_name_allows_korean_and_spaces(generator):
    assert generator.validate_workspace_dir_name("정렬 알고리즘") == "정렬 알고리즘"


@pytest.mark.parametrize("name", ["../hw1", "hw/one", "/tmp/hw", "bad:name", ""])
def test_validate_workspace_dir_name_rejects_path_like_values(generator, name):
    with pytest.raises(HTTPException):
        generator.validate_workspace_dir_name(name)


def test_safe_extract_zip_rejects_parent_traversal(generator, tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr("../escape.txt", "bad")
    data.seek(0)

    with zipfile.ZipFile(data, "r") as zf:
        with pytest.raises(HTTPException):
            generator.safe_extract_zip(zf, str(tmp_path))


def test_safe_extract_zip_rejects_symlink(generator, tmp_path):
    data = io.BytesIO()
    info = zipfile.ZipInfo("link")
    info.external_attr = (0o120777 << 16)
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr(info, "target")
    data.seek(0)

    with zipfile.ZipFile(data, "r") as zf:
        with pytest.raises(HTTPException):
            generator.safe_extract_zip(zf, str(tmp_path))


def test_safe_extract_zip_extracts_normal_files(generator, tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr("src/main.cpp", "int main() { return 0; }")
    data.seek(0)

    with zipfile.ZipFile(data, "r") as zf:
        generator.safe_extract_zip(zf, str(tmp_path))

    assert (tmp_path / "src" / "main.cpp").read_text() == "int main() { return 0; }"
