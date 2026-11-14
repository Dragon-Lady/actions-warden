"""Inert indicators: these fixtures never download, collect or send anything."""
import json
import os

import pytest

from actions_warden.cli import main
from actions_warden.scanner import scan_target


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


def types(report):
    return {f["type"] for f in report["findings"]}


@pytest.mark.parametrize("command", [
    "sh ./.ci-abcdef.sh", "bash '.ci-a1b2c3.sh'", './.ci-abcdef.sh',
    'node prepare.js && sh "./.ci-abcdef.sh"',
    'sh ./.ci-abcdef.sh >/dev/null 2>&1; node build.js',
    'node build.js; bash -e ./.ci-abcdef.sh',
    'echo $(sh ./.ci-abcdef.sh)',
])
@pytest.mark.parametrize("script", ["postinstall", "build", "prepare"])
def test_hidden_helper_in_npm_scripts(tmp_path, command, script):
    target = write(tmp_path, "package.json", json.dumps({"scripts": {script: command}}))
    before = target.read_bytes(), target.stat().st_mtime_ns
    report = scan_target(str(tmp_path))
    assert "wfx-npm-hidden-helper" in types(report)
    assert report["risk"] == "blocked"
    assert report["coverage"]["complete"]
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


@pytest.mark.parametrize("data", [
    {"scripts": {"postinstall": "node install.js"}},
    {"scripts": {"build": "sh ./build.sh"}},
    {"scripts": {"test": "echo .ci-abcdef.sh"}},
    {"scripts": {"test": "echo 'sh ./.ci-abcdef.sh'"}},
    {"scripts": {"test": "sh ./.ci-abcdefg.sh"}},
    {"scripts": {"test": "sh ./.ci-abcdef.sh.bak"}},
    {"description": "sh ./.ci-abcdef.sh", "scripts": {"test": "echo ok"}},
    {"dependencies": {"wfx-loot-example": "1.0.0"}},
])
def test_ordinary_manifests_and_lookalikes(tmp_path, data):
    write(tmp_path, "package.json", json.dumps(data))
    assert scan_target(str(tmp_path))["findings"] == []


@pytest.mark.parametrize("path", [".github/workflows/test.yml", "action.yaml", "start.sh", "nested/deploy.sh"])
def test_payload_markers_in_all_delivery_locations(tmp_path, path):
    text = "WF_CALLBACK=fixture\nWF_CTOKEN=fixture\n"
    target = write(tmp_path, path, text)
    assert "wfx-payload-markers" in types(scan_target(str(target)))
    assert "wfx-payload-markers" in types(scan_target(str(tmp_path)))


@pytest.mark.parametrize("text", [
    "WF_PRIVATE=1\nWF_EXFIL_LOG=0\n",  # no address: Telegram-only configuration
    "WF_CTOKEN=fixture\nstaging=.wfx-fixture\n",
])
def test_markers_do_not_require_a_callback_address(tmp_path, text):
    write(tmp_path, "start.sh", text)
    report = scan_target(str(tmp_path))
    assert "wfx-payload-markers" in types(report)
    assert any("missing run alone does not prove" in item for item in report["guidance"])


@pytest.mark.parametrize("text", ["WF_PRIVATE=0\n", "echo wfx\n", "# WF_CALLBACK=x WF_CTOKEN=y\n"])
def test_single_markers_and_comment_only_examples_are_not_payloads(tmp_path, text):
    write(tmp_path, "start.sh", text)
    assert scan_target(str(tmp_path))["findings"] == []


@pytest.mark.parametrize("address", ["194.150.166.244", "18.143.168.96", "153.75.82.159", "45.61.182.54"])
def test_callback_address_and_host_boundaries(tmp_path, address):
    target = write(tmp_path, "start.sh", "WF_CALLBACK=http://" + address + ":8080/exfil\n")
    assert "wfx-callback-indicator" in types(scan_target(str(target)))
    target.write_text("WF_CALLBACK=https://" + address + ".example.invalid/\n")
    assert not scan_target(str(target))["findings"]


@pytest.mark.parametrize("expression", ["toJSON(secrets)", "toJson( secrets )", "toJSON(\nsecrets\n)"])
def test_bulk_secret_context_and_outbound_detection(tmp_path, expression):
    target = write(tmp_path, ".github/workflows/ci.yml", "env:\n  DATA: ${{ " + expression + " }}\n")
    assert "workflow-bulk-secret-context" in types(scan_target(str(target)))
    target.write_text(target.read_text() + "run: " + "cur" + "l --version\n")
    assert "workflow-secret-exfiltration" in types(scan_target(str(target)))


def test_variables_and_individual_secrets_do_not_match_bulk_rule(tmp_path):
    write(tmp_path, "action.yml", "env:\n  A: ${{ toJSON(vars) }}\n  B: ${{ secrets.ONE }}\n")
    assert "workflow-bulk-secret-context" not in types(scan_target(str(tmp_path)))


@pytest.mark.parametrize("text", ["{", "[]", '{"scripts":[]}', '{"scripts":{"build":42}}'])
def test_malformed_package_json_is_incomplete(tmp_path, capsys, text):
    target = write(tmp_path, "package.json", text)
    assert main([str(target), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["coverage"]["errors"][0]["reason"] == "invalid-package-json"


@pytest.mark.parametrize("excluded", ["node_modules", ".release-venv"])
def test_dependency_directories_stay_outside_scope(tmp_path, excluded):
    write(tmp_path, excluded + "/example/package.json", '{"scripts":{"postinstall":"sh ./.ci-abcdef.sh"}}')
    write(tmp_path, "package.json", '{}')
    report = scan_target(str(tmp_path))
    assert report["summary"]["filesScanned"] == 1
    assert report["findings"] == []


def test_new_findings_never_echo_script_secrets(tmp_path):
    sentinel_text = "fixture-sensitive-value-do-not-print"
    write(tmp_path, "package.json", json.dumps({"scripts": {"build": "sh ./.ci-abcdef.sh " + sentinel_text}}))
    write(tmp_path, "start.sh", "WF_CALLBACK=" + sentinel_text + "\nWF_CTOKEN=" + sentinel_text)
    assert sentinel_text not in json.dumps(scan_target(str(tmp_path)))


def test_scripts_are_not_executed(tmp_path):
    sentinel = tmp_path / "must-not-exist"
    write(tmp_path, ".ci-abcdef.sh", "touch '" + str(sentinel) + "'\n")
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"sh ./.ci-abcdef.sh"}}')
    assert "wfx-npm-hidden-helper" in types(scan_target(str(tmp_path)))
    assert not sentinel.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink setup")
def test_symlink_helper_is_not_followed(tmp_path):
    (tmp_path / ".ci-abcdef.sh").symlink_to(tmp_path / "absent")
    report = scan_target(str(tmp_path))
    assert not report["coverage"]["complete"]
    assert report["coverage"]["errors"][0]["reason"] == "symlink-skipped"


def test_unsupported_single_file_is_rejected(tmp_path):
    target = write(tmp_path, "notes.txt", "ordinary text")
    with pytest.raises(ValueError, match="Unsupported"):
        scan_target(str(target))


def test_deep_json_is_incomplete(tmp_path, capsys):
    target = write(tmp_path, "package.json", "[" * 2000 + "0" + "]" * 2000)
    assert main([str(target), "--json"]) == 1
    assert not json.loads(capsys.readouterr().out)["coverage"]["complete"]
