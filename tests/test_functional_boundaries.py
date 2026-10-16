"""Regression checks for incomplete scans and non-destructive report output."""

import json
import os
from contextlib import contextmanager

import pytest

from actions_warden import cli, scanner


@pytest.fixture
def source(tmp_path):
    target = tmp_path / "action.yml"
    target.write_text("name: ordinary fixture\n")
    return target


@pytest.mark.parametrize("args", [
    ["--unknown"], ["--report"], ["--report", "--json"], ["--report="], [".", "."],
])
def test_invalid_arguments(args, capsys):
    assert cli.main(args) == 1
    assert "Error:" in capsys.readouterr().err


def test_help_does_not_scan(monkeypatch, capsys):
    def unexpected(*args):
        pytest.fail("help must not scan")
    monkeypatch.setattr(cli, "scan_target", unexpected)
    assert cli.main(["--help"]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_missing_and_empty_targets(tmp_path, capsys):
    assert cli.main([str(tmp_path / "absent")]) == 1
    assert cli.main([str(tmp_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["coverage"]["complete"]
    assert report["summary"]["filesScanned"] == 0


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX special file")
def test_special_file_rejected(tmp_path, capsys):
    target = tmp_path / "action.yml"
    os.mkfifo(target)
    assert cli.main([str(target)]) == 1
    assert "regular file or directory" in capsys.readouterr().err


@pytest.mark.parametrize("helper", ["_safe_size", "_read_text"])
def test_candidate_failure_is_incomplete(source, monkeypatch, capsys, helper):
    monkeypatch.setattr(scanner, helper, lambda _: None)
    assert cli.main([str(source), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert not report["coverage"]["complete"]
    assert report["coverage"]["errors"][0]["path"] == str(source)
    assert report["summary"]["filesSkipped"] == 1
    assert report["summary"]["filesScanned"] == 0


def test_traversal_failure_is_incomplete(tmp_path, monkeypatch, capsys):
    denied = tmp_path / "denied"
    denied.mkdir()
    original = os.scandir
    def scandir(path):
        if str(path) == str(denied):
            raise PermissionError("fixture denial")
        return original(path)
    monkeypatch.setattr(os, "scandir", scandir)
    assert cli.main([str(tmp_path), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["coverage"] == {
        "complete": False, "errors": [{"path": str(denied), "reason": "list-error"}],
    }
    assert cli.main([str(tmp_path)]) == 1
    assert "INCOMPLETE" in capsys.readouterr().out


def test_file_budget_is_incomplete(source):
    report = scanner.scan_target(str(source), max_file_bytes=1)
    assert not report["coverage"]["complete"]
    assert report["coverage"]["errors"][0]["reason"] == "size-limit"


def test_blocking_findings_survive_incomplete_coverage(source, monkeypatch, capsys):
    report = scanner.scan_target(str(source))
    report["risk"] = "blocked"
    report["coverage"] = {"complete": False, "errors": []}
    monkeypatch.setattr(cli, "scan_target", lambda _: report)
    assert cli.main([str(source), "--json"]) == 2
    assert not json.loads(capsys.readouterr().out)["coverage"]["complete"]


@pytest.mark.parametrize("kind", ["same", "symlink", "hardlink", "parent-symlink",
                                  "dangling-symlink", "unrelated", "new"])
def test_report_preserves_existing_inputs(source, tmp_path, kind, capsys):
    destination = tmp_path / "report.json"
    if kind == "same":
        destination = source
    elif kind == "symlink":
        destination.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, destination)
    elif kind == "parent-symlink":
        parent = tmp_path / "alias"
        parent.symlink_to(tmp_path, target_is_directory=True)
        destination = parent / source.name
    elif kind == "dangling-symlink":
        destination.symlink_to(tmp_path / "missing")
    elif kind == "unrelated":
        destination.write_text("old report")
    before = source.read_bytes(), source.stat()
    old_umask = os.umask(0)
    try:
        code = cli.main([str(source), "--report", str(destination), "--json"])
    finally:
        os.umask(old_umask)
    assert source.read_bytes() == before[0]
    for key in ("st_ino", "st_size", "st_mtime_ns", "st_mode"):
        assert getattr(source.stat(), key) == getattr(before[1], key)
    if kind == "new":
        assert code == 0
        assert json.loads(destination.read_text())["coverage"]["complete"]
        if os.name == "posix":
            assert destination.stat().st_mode & 0o777 == 0o600
    else:
        assert code == 1
        assert "Error:" in capsys.readouterr().err
        if kind == "unrelated":
            assert destination.read_text() == "old report"
        if kind == "dangling-symlink":
            assert not (tmp_path / "missing").exists()


def test_report_write_failure_is_not_success(source, tmp_path, monkeypatch, capsys):
    original = os.fdopen
    closed = []
    @contextmanager
    def failing_writer(fd, *args, **kwargs):
        with original(fd, *args, **kwargs) as handle:
            class Writer:
                def write(self, data):
                    handle.write(data[:4])
                    raise OSError("fixture write failure")
            try:
                yield Writer()
            finally:
                closed.append(fd)
    monkeypatch.setattr(os, "fdopen", failing_writer)
    before = source.read_bytes()
    destination = tmp_path / "failed-report.json"
    assert cli.main([str(source), "--report", str(destination)]) == 1
    assert "fixture write failure" in capsys.readouterr().err
    assert source.read_bytes() == before
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])

