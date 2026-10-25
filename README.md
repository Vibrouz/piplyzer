# piplyzer

Project description: supply-chain gate for GitHub Actions and npm dependencies. Scans workflow YAML (14 rules: PPE-001–PPE-014) and lockfiles (DEP-D1/D2). Runs as CLI, reusable Action, or self-hosted GitHub App posting required check runs. Single Go binary (v1.0.0), pinned by commit SHA, external to repo (not editable by PR authors).

**piplyzer** scans GitHub Actions workflows and npm lockfiles for supply chain attack patterns. It runs as a standalone CLI, a GitHub Action, or a self-hosted GitHub App that posts check runs on pull requests - so the gate cannot be bypassed by editing the workflow file.

## What it checks

### Workflow rules (piplyzer scan)

| Rule | ID | Tier | What it catches |
|------|-----|------|-----------------|
| Unpinned actions | PPE-001 | Block | `uses: owner/repo@v4` instead of a full 40-char commit SHA |
| Untrusted context in `run:` | PPE-002 | Block/Warn | `${{ github.event.pull_request.title }}` interpolated into shell |
| Remote script execution | PPE-003 | Block | `curl ... \| bash`, `wget -qO- ... \| sh` |
| Bare IP / `http://` in `run:` | PPE-004 | Block/Warn | Literal IP address or plain HTTP endpoint |
| Credential in `run:` | PPE-005 | Block | AWS keys, GitHub PATs, private keys, OpenAI/Slack tokens |
| Deep checkout + history scan | PPE-006 | Block | `fetch-depth: 0` + `git log -p` / `git rev-list` / `git show` |
| Unfiltered `on: push` | PPE-007 | Warn | Workflow runs on every push to any branch |
| `workflow_dispatch` on privileged job | PPE-008 | Warn | Manual trigger on a job that holds secrets |
| Pwn request (`pull_request_target` / `workflow_run` + untrusted checkout) | PPE-009 | Block | Privileged trigger that runs fork code with repo secrets |
| Cross-repo `uses:` we cannot read | PPE-010 | Warn | References to third-party actions (exempts `actions/*`, `github/*`) |
| OIDC token overgrant | PPE-011 | Block | `permissions: id-token: write` without audience restriction |
| Action fingerprint match | PPE-012 | Block | Known-bad action version (e.g., tj-actions/changed-files@CVE-2025-30066) |
| `secrets: inherit` to another repo | PPE-013 | Block | Hands all secrets to a workflow in a different repository |
| Secret used as structured value | PPE-014 | Block | `fromJSON(secrets.X).field` or `toJSON(secrets)` - runner cannot redact |

### Dependency rules (piplyzer deps)

| Rule | ID | Tier | What it catches |
|------|-----|------|-----------------|
| New package | DEP-D1 | Warn | Package path not in base lockfile (typosquat vector) |
| Install script appeared | DEP-D2 | Block | Same path, no script in base, script in head |
| New package + install script | DEP-D1D2 | Block | Highest-signal shape: unreviewed package that runs code at install |

## Setup

You can use piplyzer in three ways:

1. **Standalone CLI** - run `piplyzer scan .` locally on your repo
2. **GitHub Action** - add `.github/workflows/piplyzer.yml` to your repo
3. **Self-hosted GitHub App** - the App posts a required check on every PR

### Install

```bash
# From source
go build -o piplyzer ./cmd/ppe

# Or download a release binary
curl -L -o piplyzer https://github.com/Vibrouz/piplyzer/releases/download/v1.0.0/piplyzer-linux-amd64
chmod +x piplyzer
```

### Quick start (CLI)

```bash
# Scan workflows in the current repo
piplyzer scan .

# Check npm dependencies (needs package-lock.json)
piplyzer deps .

# Scan a single workflow from stdin
cat .github/workflows/ci.yml | piplyzer scan -

# Print version
piplyzer --version
```

**Exit codes**
- `0` - check finished, nothing blocks (warnings may be printed)
- `1` - at least one **Block** finding (the merge gate)
- `2` - check did not finish (bad args, unreadable file, no workflows found)

### GitHub Action (reusable workflow)

```yaml
# .github/workflows/piplyzer.yml
name: piplyzer
on:
  pull_request:
  push:
    branches: [main]

jobs:
  piplyzer:
    uses: Vibrouz/piplyzer/.github/workflows/piplyzer.yml@<commit sha>
```

Pin the commit named in the release notes, not the tag: the scanner blocks movable tags (PPE-001), and it would block this reference too.

The action downloads the `piplyzer` binary, runs `piplyzer scan` on `.github/workflows`, and runs `piplyzer deps` if `package-lock.json` exists. It skips gracefully when neither is present.

### Self-hosted GitHub App

The App posts a **required check run** on every pull request. Because the check runs outside the workflow, a compromised maintainer cannot disable it by editing the workflow file.

Choose one setup path:

#### A. Automated local runner (easiest for testing)

```bash
./scripts/local.sh
```

This builds the `piplyzer` binary, creates the GitHub App via the manifest flow, writes `.piplyzer/app.pem` and `.piplyzer/config.env` (mode 0600), starts the check server on `127.0.0.1:8080`, opens a Quick Tunnel, and updates the App webhook URL.

Override defaults:
```bash
PIPLYZER_CONFIG_DIR=.piplyzer PIPLYZER_PORT=8082 ./scripts/local.sh
```

#### B. Manual setup + serve (full control)

1. **Build the binary**
   ```bash
   go build -o piplyzer ./cmd/ppe
   ```

2. **Create the App**
   ```bash
   piplyzer setup [--hook-url https://your.domain/webhook] [--config-dir DIR]
   ```

3. **Open the local page** (`http://127.0.0.1:8081/` by default) in your browser.

4. **Complete the manifest** - GitHub creates the App and shows the private key **exactly once**. If you close the tab before the key lands in `.piplyzer/app.pem`, the App is stranded.

5. **Install the App** on target repositories:
   ```
   https://github.com/apps/<slug>/installations/new
   ```

6. **Add a branch ruleset** that requires the `piplyzer` check before merge. In your repository settings (Settings > Rules > Rulesets):
   - Create a new ruleset (or edit existing)
   - Set target branches to the protected branch pattern (e.g., `main`)
   - Enable "Require status checks to pass before merging"
   - Click "Add status check"
   - Select `piplyzer` as the source (the App, not just the check name)
   - Optionally check "Require branches to be up to date before merging" (strict mode)
   - Save the ruleset

   Required status checks are evaluated on push as well as merge, and the App only posts checks on pull requests, so a direct push to the protected branch is rejected. If maintainers need to push directly, add them to the ruleset's bypass list (for example Repository admin). Otherwise keep the branch PR-only.

7. **Run the webhook server**
   ```bash
   piplyzer serve --addr :8080
   ```

   Required environment variables (written by `piplyzer setup`):
   - `PIPLYZER_APP_ID`
   - `PIPLYZER_PRIVATE_KEY_PATH`
   - `PIPLYZER_WEBHOOK_SECRET`

#### C. Standalone install with custom webhook (no tunnel)

Use `--hook-url` to skip the placeholder and point the App directly at your public webhook URL.

```bash
piplyzer setup --hook-url https://your.domain/webhook
```

No local runner needed. The App is active immediately after manifest completion.

### Common issues

| Problem | Fix |
|---------|-----|
| `.piplyzer/app.pem` already exists | `setup` refuses to overwrite. Remove the directory or use a different `--config-dir`. |
| No `--hook-url` and no local runner | Webhook stays on the placeholder (`https://example.com/piplyzer-webhook`) and receives nothing. Use `--hook-url` for standalone installs. |
| Ruleset requires `ppe` | Old check name; update the ruleset to require `piplyzer`. |
| Direct push to `main` is rejected | The check only runs on pull requests. Add a bypass actor or open a pull request. |

## Design principles

- **Pure scan**: The scan is a pure function over workflow text. It never runs a workflow, resolves an action, or calls the GitHub API. Every claim is about text in the repository.
- **Exit code semantics**: `0` = clean, `1` = blocking finding, `2` = incomplete scan. A gate that reports "clean" when it looked at nothing is worse than a false alarm.
- **Block by default**: Every finding blocks except those explicitly tiered Warn. Warn is for findings a reader can triage; Block is for findings that must stop the merge.
- **No config file (yet)**: Rules are hardcoded. When configuration lands, the current behaviour becomes the default.
- **Self-hosted App**: The check source is external to the workflow, so the gate cannot be bypassed by editing the workflow file.

## Project structure

```
cmd/ppe/           # CLI entry points: scan, deps, serve, setup
internal/
  parse/           # YAML workflow parser
  engine/          # Orchestrates rules against parsed workflows
  rules/           # PPE-001 through PPE-014, DEP-D1/D2/D1D2
  findings/        # Finding types, severity, sorting
  deps/            # Lockfile diff logic (D1, D2, D1D2)
  lockfile/        # package-lock.json parser (v1, v2, v3)
  repofetch/       # GitHub API client for the App
  appauth/         # GitHub App authentication
  webhook/         # Webhook server (serve command)
  check/           # Check run payload builder
tests/fixtures/    # Golden test fixtures for each rule
```
