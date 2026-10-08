# CHECKPOINT — release 0.63.0 (zappa/Zappa)

Written 2026-10-08 15:04 JST. Supersedes the 2026-10-05 checkpoint. All datetimes JST.

## Git state

- Branch `release/0.63.0` at `bb40159` (`:bookmark: Bump version to 0.63.0`), pushed, PR **#1476**.
- `origin/master`: `e915fa6` — `Skip keep-warm import of handler.keep_warm_callback (#1469) (#1470)`

## Release 0.63.0

| Step | Status (2026-10-08 15:04) |
|---|---|
| CHANGELOG: `## 0.63.0` covers all 18 commits since `0.62.1`; adds missing `## 0.62.1` / `## 0.62.0` | Done (#1476) |
| `zappa/__init__.py` `0.62.1` → `0.63.0` | Done (#1476) |
| #1476 CI (`test (3.9)`–`test (3.14)`, `coverage`) | Passed |
| #1476 approving review + squash-merge | **Pending** (`REVIEW_REQUIRED`) |
| `CD` workflow, `version=0.63.0`, dry run then real run (tag, GitHub Release, PyPI) | **Pending** |
| Comment on #1474 and #1463 that 0.63.0 ships the fix (do not close) | **Pending** |

## Merge queue

All of #1465, #1473, #1462, #1467, #1468, #1470 are merged. Only #1452 remains:

- **#1452** deprecate keep_warm — open, `MERGEABLE`, `[needs-review]`, not in 0.63.0.
  Drop the runtime `DeprecationWarning` inside `keep_warm_callback` (dead code since #1470); keep the
  `click.echo` in `cli.schedule()`. Remove the redundant `"keep_warm": false` lines from
  `example/zappa_settings.json`. Add a CHANGELOG entry under `## Unreleased`.

## Remaining tasks

1. Finish the release steps above.
2. **#1468 README follow-up** (docs PR). Gaps not covered by the merged PR:
   - `README.md:449` §Rollback — rollback now moves ALB/`snapstart`/`provisioned-concurrency` aliases;
     each update publishes **two** versions with SnapStart/PC, so `rollback -n 1` lands on the same
     deploy's code-only version; `-n 2` goes back one deploy.
   - `apigateway_lambda_qualifier` custom alias: Zappa never creates or moves it — it must pre-exist
     and be repointed manually after each update.
   - Function URLs, `keep_warm`, and `events` still invoke `$LATEST` (no SnapStart/PC benefit).
   - PC is double-provisioned during update; update waits up to 600 s for `READY`.
   - §Cold Starts mentions Provisioned Concurrency — link to the new setting.
   - Move the three long single-line settings comments into a dedicated section.
3. **#1468 code follow-ups** (issues): orphaned PC billing on a failed deploy between
   `put_provisioned_concurrency_config` and alias migration; ALB alias can be stranded when SnapStart
   defers ALB migration to `update_lambda_configuration`.
4. **#1475** — reply inviting a PR for items 1 and 2 (unguarded `s3.Object(...).get()` at
   `zappa/handler.py:231`; README §Large Projects never says the archive must be retained). Defer item 3.
5. **#1471** — community.md listing; invite the PR.

## Decisions made

- **CHANGELOG is hand-maintained.** `cd.yml` only generates GitHub Release notes
  (`generateReleaseNotes: true`); the `tag` job's `changelog` output is unused. Entries are written at
  release time.
- **Never close issues** unless explicitly requested; avoid closing keywords (`Resolves #N`) in PR bodies.
- Merge method: **squash only**. `delete_branch_on_merge` is on.
- Merge, not rebase, on third-party fork branches (avoids force-pushing).

## Open questions

1. Delete stale local branches `pr-1467-black`, `pr-1467-check`, `pr1467-remote`, `pr1467-resolve`,
   `pr1468`, `pr1468-review-tmp`?
2. Reopen #1451 / #1445? Auto-closed `NOT_PLANNED` by the stale bot while #1452 is open.

## Environment notes

- CI: `.github/workflows/ci.yml`, matrix 3.9–3.14, `pipenv run make flake black-check isort-check`
  then `pipenv run make tests`, then Coveralls.
- `master` protection: 1 approving review + required contexts `test (3.9)`–`test (3.12)`, `coverage`.
- Release: `.github/workflows/cd.yml` (`workflow_dispatch`, inputs `dry-run`, `version`).
- Fork PRs need workflow approval on every push:
  `gh run list --status action_required` → `gh api -X POST repos/zappa/Zappa/actions/runs/<id>/approve`
- Stale bot (`.github/workflows/maintenance.yml`): 90 days → `no-activity`, +10 days → closed.
  Exemption label: `needs-review`.
- This project uses **pipenv**. Tests: `pipenv run pytest tests/`.
