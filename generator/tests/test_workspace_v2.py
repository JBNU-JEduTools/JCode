import asyncio
import errno
import io
import json
import os
import stat
import zipfile

import pytest


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def test_environment_profiles_reject_inconsistent_presets(generator):
    with pytest.raises(generator.HTTPException) as error:
        generator.validate_workspace_profile(
            "ALGORITHM", True, False, None, "STANDARD", "PACKAGE_PROXY", "COURSE"
        )
    assert error.value.status_code == 409

    generator.validate_workspace_profile(
        "LAB", True, True, None, "STANDARD", "PACKAGE_PROXY", "COURSE"
    )


def test_custom_profile_requires_immutable_harbor_image(generator):
    with pytest.raises(RuntimeError):
        generator.validate_workspace_profile(
            "CUSTOM", False, True, "docker.io/example/latest", "GPU", "RESTRICTED", "ASSIGNMENT"
        )


def test_resource_profile_values_are_loaded_from_environment(generator, monkeypatch):
    monkeypatch.setenv(
        "WORKSPACE_RESOURCE_PROFILES_JSON",
        json.dumps({"STANDARD": {"requests": {"cpu": "100m"}, "limits": {"memory": "1Gi"}}}),
    )
    resources = generator.get_workspace_resources("STANDARD")
    assert resources.requests == {"cpu": "100m"}
    assert resources.limits == {"memory": "1Gi"}


def test_starter_distribution_preserves_or_replaces_student_files(generator, monkeypatch, tmp_path):
    monkeypatch.setattr(os, "chown", lambda *_: None)
    artifact = tmp_path / "starter.zip"
    make_zip(artifact, {"main.py": "starter", "new.txt": "new"})
    target = tmp_path / "assignment-1"
    target.mkdir()
    (target / "main.py").write_text("student", encoding="utf-8")

    generator.apply_starter_artifact(artifact, target, "PRESERVE_EXISTING")
    assert (target / "main.py").read_text(encoding="utf-8") == "student"
    assert (target / "new.txt").read_text(encoding="utf-8") == "new"

    generator.apply_starter_artifact(artifact, target, "REPLACE_ALL")
    assert (target / "main.py").read_text(encoding="utf-8") == "starter"

    with pytest.raises(generator.HTTPException, match="checksum"):
        generator.verify_artifact_checksum(artifact, "0" * 64)


def test_starter_distribution_rejects_student_symlink(generator, monkeypatch, tmp_path):
    artifact = tmp_path / "starter.zip"
    make_zip(artifact, {"main.py": "starter"})
    outside = tmp_path / "outside"
    outside.mkdir()
    target_parent = tmp_path / "student"
    target_parent.mkdir()
    (target_parent / "assignment-1").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(os, "chown", lambda *_: None)

    with pytest.raises(generator.HTTPException, match="symlink"):
        generator.apply_starter_artifact(artifact, target_parent / "assignment-1", "PRESERVE_EXISTING")


def test_starter_upload_validation_rejects_symlink_member(generator, tmp_path):
    artifact = tmp_path / "starter.zip"
    member = zipfile.ZipInfo("linked-file")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(member, "outside")

    with zipfile.ZipFile(artifact, "r") as archive:
        with pytest.raises(generator.HTTPException, match="symlink"):
            generator.validate_zip_archive(archive, str(tmp_path / "extract"))


def test_assignment_path_migration_is_idempotent(generator, monkeypatch, tmp_path):
    workspace_root = tmp_path / "workspace"
    student = workspace_root / "os-1-20260001"
    legacy = student / "old-name"
    legacy.mkdir(parents=True)
    (legacy / "answer.py").write_text("pass", encoding="utf-8")
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))
    monkeypatch.setattr(generator, "COURSE_NAMESPACE_PREFIX", "jcode-")
    monkeypatch.setattr(generator, "resolve_namespace", lambda value: value)
    monkeypatch.setattr(generator, "verify_course_namespace", lambda *_: None)
    monkeypatch.setattr(generator.client, "CoreV1Api", lambda: object())
    monkeypatch.setattr(os, "chown", lambda *_: None)
    request = generator.AssignmentProvisionRequest(
        course_id=1,
        namespace="jcode-os-1",
        workspace_key="assignment-7",
        legacy_dir_name="old-name",
    )

    first = asyncio.run(generator.provision_assignment_workspace(request, {}))
    second = asyncio.run(generator.provision_assignment_workspace(request, {}))

    assert first["migrated"] == 1
    assert second == {"workspace_key": "assignment-7", "migrated": 0, "created": 0}
    assert (student / "assignment-7" / "answer.py").is_file()


def test_archive_move_supports_different_filesystems(generator, monkeypatch, tmp_path):
    source = tmp_path / "workspace" / "assignment-1"
    destination = tmp_path / "archive" / "assignment-1"
    source.mkdir(parents=True)
    (source / "answer.py").write_text("pass", encoding="utf-8")
    original_rename = generator.Path.rename

    def cross_device_rename(path, target):
        if path == source:
            raise OSError(errno.EXDEV, "cross-device link")
        return original_rename(path, target)

    monkeypatch.setattr(generator.Path, "rename", cross_device_rename)
    generator.move_directory_safely(source, destination, {"retention_days": 90})

    assert not source.exists()
    assert (destination / "answer.py").read_text(encoding="utf-8") == "pass"
    assert json.loads((destination / ".retention.json").read_text())["retention_days"] == 90


def test_reopen_prepares_workspace_for_student_without_final_archive(generator, monkeypatch, tmp_path):
    workspace_root = tmp_path / "workspace"
    student = workspace_root / "os-1-20260001"
    student.mkdir(parents=True)
    artifact = tmp_path / "starter.zip"
    make_zip(artifact, {"main.py": "starter"})
    monkeypatch.setattr(generator, "NFS_MOUNT_PATH", str(tmp_path))
    monkeypatch.setattr(generator, "COURSE_NAMESPACE_PREFIX", "jcode-")
    monkeypatch.setattr(generator, "get_workspace_archive_root", lambda: tmp_path / "archive")
    monkeypatch.setattr(os, "chown", lambda *_: None)

    moved = generator.move_assignment_between_workspace_and_final_archive(
        "jcode-os-1",
        "assignment-7",
        90,
        restore=True,
        starter_artifact=artifact,
    )

    assert moved == 1
    assert (student / "assignment-7" / "main.py").read_text(encoding="utf-8") == "starter"
