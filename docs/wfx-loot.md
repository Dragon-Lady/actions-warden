# wfx-loot: local checks and historical review

Actions Warden 0.1.6 adds static checks for the campaign reported in November
2026. It reads selected files only, never runs an install hook or workflow, and
does not contact GitHub or change credentials. These checks help identify
reported structures; they cannot guarantee prevention or establish execution.

## What the local scan adds

- Workflows that serialize the entire secrets context. Pass only the specific
  credentials a step needs; moving all secrets into an environment variable
  does not make that export safe.
- Combined wfx-loot configuration and staging markers in workflows and `.sh`
  scripts. Matching does not depend on a network address being present, so it
  also covers reported marker combinations used in Telegram-only delivery.
- Reported callback addresses accompanied by callback/network syntax, with
  address boundaries to avoid matching a different host with a similar name.
- Commands in `package.json` scripts that invoke the reported hidden shell
  helper filename pattern. Ordinary hooks, descriptions and dependencies are
  not automatically flagged. A filename-pattern match still needs inspection.

The scanner does not inspect `node_modules`, downloaded packages, archived
artifacts, Git objects, or arbitrary script languages. Malformed manifests,
unreadable candidates and skipped candidate symlinks produce incomplete
coverage. New campaign findings omit source snippets to avoid copying secrets
into the report. Existing workflow rules keep their established output format.

## Review the history as well

The main wave began on November 10; GitGuardian describes a precursor from
October 24 to 29. Review repositories the account can write to, including
collaborator access. Check pull requests, branches, commit history, workflow
records and organization/account security logs where available. The reported
probe title is `docs: dependency audit notes`, usually from `wfx-docs`.

An unexpected probe created using your account or a bot account you control
is evidence to investigate that account's access. A similarly titled PR from
an outside account does not by itself prove your own account was compromised.

Attackers also used install/build hooks or appended shell scripts, then
reverted changes. Inspect historical `package.json` scripts and shell files,
not only workflow definitions and the current checkout. A missing workflow
run is a review lead, not proof a job ran or data left the runner. The API can
also be missing deleted branches, runs and logs; absence is not assurance.

## If execution or exposure is established

Preserve the relevant evidence and stop executing the affected code. Use a
trusted environment to remove the attacker's account access and rotate the
credentials the affected job or developer process could reach. Review cloud
audit records and persistence, including newly created AWS keys, changed role
trust policies and Azure federated identities. Rotation alone cannot remove
an added trust relationship. Assess package publishing and developer machines
that installed dependencies during the affected interval.

This is response guidance, not an automatic cleanup procedure. Actions Warden
does not revoke credentials, delete evidence, alter cloud policies or determine
which historical jobs executed.

## Primary research

- [Aikido: campaign overview and payload analysis, November 12](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories)
- [GitGuardian: delivery forms, npm bypass and execution evidence, November 13](https://blog.gitguardian.com/wfx-loot-a-ci-secret-stealer-pushed-with-stolen-github-credentials/)
- [SafeDep: credential stealer analysis, November 12](https://safedep.io/blog/github-actions-wfx-credential-stealer)

Sources describe evolving samples. Counts and observed delivery channels differ
by time and dataset; the scanner does not embed a live incident total.
