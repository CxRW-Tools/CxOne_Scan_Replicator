# cxone-scan-replicator

Re-scan the source code of existing Checkmarx One (CxOne) scans in a **second tenant**. For each scan ID the
tool reads the scan's project/branch/tags in **Source tenant**, downloads the exact scanned source, finds or creates a
same-named project in **Target tenant**, uploads the source as a zip and **starts a scan** on the same branch. It exits
once every scan has been *started*; it never waits for scans to finish.

> **Status:** the code is covered by an automated test suite against a fake HTTP layer for both tenants
> (92 tests, including 2,000-scan runs). It has **not** been run against a live tenant yet. Work through the
> [live-tenant checklist](#verify-on-a-live-tenant-before-the-first-big-run) first.

Three modes:

| Mode | Command shape | Contacts |
|---|---|---|
| **Replicate** (default) | `--scan-ids/--scan-ids-file` + `--scan-types` | Source tenant + Target tenant |
| **Download-only** | `--download-only --output-dir DIR` | Source tenant only |
| **From manifest** | `--from-manifest DIR --scan-types ...` | Target tenant only |

Every mode writes a text log, a JSONL audit trail, a CSV report, keeps a resumable state DB, and shows a live
status screen.

## Setup

```bash
pip install -r requirements.txt     # requests, python-dotenv, rich  (Python 3.10+)
pip install pytest                  # only to run the tests
python -m pytest tests -q
```

### Env files

Credentials live in **one file per tenant**, in the same format as the CxOne tool template
(`.env.source.example`, `.env.target.example`):

```
CXONE_BASE_URL=https://ast.checkmarx.net
CXONE_TENANT=my-tenant
CXONE_API_KEY=eyJ...
CXONE_DEBUG=false
```

```bash
python main.py --source-env-file C:\envs\.env.rw_demo --target-env-file C:\envs\.env.cx_canary     --scan-types sast,sca --scan-ids-file scan-ids.txt --dry-run
```

* `--source-env-file` = Source tenant, `--target-env-file` = Target tenant. Download-only needs only the source file;
  `--from-manifest` only the target file. The un-prefixed `CXONE_*` names are read **only** from these files
  (never from the process environment), so the two tenants cannot be mixed up.
* Only the API key is required. Anything omitted is derived: tenant and base URL from the key's JWT, and the
  IAM URL from the base URL (`ast.` → `iam.`, as in the CxOne template), falling back to the JWT issuer. Set
  `CXONE_IAM_URL` only if that guess is wrong. (`--t1-*`/`--t2-*` remain as aliases of `--source-*`/`--target-*`.)
* The configured values are cross-checked against the API key's JWT: a tenant that differs from the key's is **fatal**, an expired key is fatal, and an IAM/base-URL host that differs from the key's issuer region is a **warning**.
* Non-credential settings (`REPLICATOR_SCAN_TYPES`, `REPLICATOR_OUTPUT_DIR`, ...) go in an optional
  `--env-file` (repeatable; later files win; `./.env` is loaded only if no `--env-file` is given), or on the CLI.
  Legacy `CXONE_T1_*` / `CXONE_T2_*` variables in that file/environment still work at lower priority.
* A missing/unreadable file is fatal (exit 1). Files are read with `dotenv_values`, never written to `os.environ`.

| Value | Precedence (highest first) |
|---|---|
| tenant field | CLI flag > that tenant's env file > legacy `CXONE_T1_*`/`CXONE_T2_*` (`--env-file`, environment) > JWT |
| other option | CLI flag > `--env-file` (last file wins) > process environment > built-in default |
| `--scan-types` | CLI > `REPLICATOR_SCAN_TYPES` in env file > process env > each scan's original engines |

The preflight banner (stderr) prints the mode, scan types, env files and each tenant's resolved name/URLs with
the **source of each value** (`cli`, `env-file:<path>`, `environment`, `jwt`). Key values are never printed.
Replicate mode refuses to run if both tenants resolve to the same tenant + base URL (`--allow-same-tenant`
overrides).

## Scan types (`--scan-types`)

Optional for Replicate and `--from-manifest`. **If omitted, each scan runs the supported engines of its original scan** (its `engines`, mapped to `sast`/`iac`/`api`/`sca`; containers, secrets/microengines etc. are dropped; a scan with none of the four fails with `no_supported_engines`). If given, the same selection applies to every scan. Comma-separated, case-insensitive, de-duplicated and normalized to
the order `sast, iac, api, sca`.

| You type | Aliases | API `config[].type` | Label |
|---|---|---|---|
| `sast` | | `sast` | SAST |
| `iac` | `kics` | `kics` | IaC (KICS) |
| `api` | `apisec` | `apisec` | API Security |
| `sca` | | `sca` | SCA |

* With an explicit `--scan-types`, the same selection is applied to **every** scan, regardless of what the original scan ran.
* Each engine is sent with `"value": {}`: no preset, no incremental flag. Target tenant's defaults decide. (Opt-in
  `--force-tenant-defaults` sends the tenant-level SAST `presetName`/`incremental` explicitly.)
* Anything else (`containers`, `secrets`, `2ms`, `microengines`, `scorecard`, `aisc`, `cisec`, `fusion`, ...) is
  rejected before any network call, as is an empty list.
* `api` without `sast` logs a warning (API Security may depend on SAST).
* The selection is recorded in the run row, per job, in the audit trail, as a report column and as the Target tenant
  scan tag `cx-replicated-scan-types`.

**Duplicates vs scan types:** de-duplication is by *source scan ID only*. A scan already replicated is skipped
even if this run selects different types. To re-scan with different types, use `--ignore-duplicates`
(asks for confirmation; `--yes-ignore-duplicates` to skip that prompt).

## Modes

### Replicate

```bash
python main.py --source-env-file .env.source --target-env-file .env.target --scan-types sast,iac,api,sca --scan-ids-file ids.txt --dry-run
python main.py --source-env-file .env.source --target-env-file .env.target --scan-types sast,sca --scan-ids-file ids.txt --yes
```

Per scan: metadata (Source tenant) → source `HEAD` → download (memory up to `--memory-zip-max-mb`, otherwise a 0600
temp file, with a global `--memory-budget-mb`) → find/create project (name only) → upload → `POST /api/scans`.
Scans are processed oldest-first (`createdAt`), and scans of one project are **started in that order**, one at
a time per project. Tags copied from the original scan plus:
`cx-replicated-from-scan`, `-from-tenant`, `-from-project`, `-scan-types`, `-at`.

### Download-only

```bash
python main.py --source-env-file .env.source --download-only --output-dir ./src-export --scan-ids-file ids.txt
python main.py --source-env-file .env.source --download-only --no-save-zips --scan-ids-file ids.txt   # verify availability only
```

Target tenant is never contacted; `--scan-types` is ignored (with a notice). Zips are written to `<name>.zip.part`,
fsynced and atomically renamed. `--layout flat` → `<scan_id>.zip`; `--layout by-project` →
`<project>/<branch>/<scan_id>.zip` (names sanitized, hash suffix when altered or trimmed; the manifest keeps the
originals). Existing file with a matching SHA-256 from an earlier run → skipped; different content →
`file_exists` unless `--overwrite`. Downloads pause while free disk space is below `--min-free-gb`.
The output dir is created `0700`; the zips contain customer source code (a warning is printed inside a git tree).

### From manifest

```bash
python main.py --target-env-file .env.target --from-manifest ./src-export --scan-types iac,sca --yes
```

Source tenant is never contacted. Zips are verified against the manifest SHA-256 (`manifest_zip_missing` /
`manifest_zip_corrupt`) and are **never deleted**. `--scan-ids` / `--scan-ids-file` restrict to a subset.

### Manifest format (stable contract, version 1)

`<dir>/manifest.jsonl`: one JSON object per line; `<dir>/manifest.csv`: same fields (`tags`, `source_engines`
as JSON text). Written incrementally (append + flush). Readers take the **last row per `source_scan_id`**;
`--compact-manifest` rewrites both files with one row per ID.

`manifest_version, source_scan_id, t1_tenant, t1_base_url, t1_project_id, project_name, branch, source_status,
source_created_at, source_engines, tags, status (SAVED|VERIFIED|FAILED), error_code, error_message,
zip_path (relative to the dir; empty for VERIFIED), zip_bytes, zip_sha256, downloaded_at, tool_version, run_id`

`source_engines` is informational; the engines run in Target tenant always come from that run's `--scan-types`.

## Throttling and the Target tenant queue

No start rate limit; download+upload time paces the run. At startup, and after every `--queue-check-every`
(100) scans started, the Target tenant queue is read (`GET /api/scans/summary`, falling back to counting
`statuses=Queued` rows). If `Queued` > `--queue-max` (500), **uploads and starts pause**; the tool sleeps
`--queue-pause-seconds` (300), re-checks, and resumes or keeps waiting. `--queue-count running` counts
Queued+Running. Downloads continue only until the bounded stage queues/memory budget fill.

Other load controls: per-tenant concurrency caps (`--source/--target-max-concurrency`), `Retry-After` handling, and AIMD
(concurrency halves on repeated 429s, +1 per 50 successes), bounded stage queues, one pooled session per tenant.

## Re-runs, resume, Ctrl-C

State lives in `--state-db` (SQLite, keyed by mode + source scan ID) **and** in the migration tags on Target tenant
scans. Re-running with the same input is safe in every mode: started/saved jobs are skipped, `FAILED` ones only
retried with `--retry-failed`, crashed in-flight jobs reset to `PENDING`, and anything that may have reached
"start scan" is checked against Target tenant before being started again. Resuming with different `--scan-types`
updates not-yet-started jobs to the new selection.

First Ctrl-C: stop admitting jobs, finish in-flight work, flush everything, print the summary (exit 130).
Second Ctrl-C: abort immediately (state stays resumable; leftover `.part` files are cleaned next run).

## Required permissions

* **Source tenant:** view scans, download source code.
* **Target tenant:** create projects, create scans, view scans (de-dup and queue checks use scan listings).

## Flag reference

| Flag | Default | Notes |
|---|---|---|
| `--source-env-file PATH` / `--target-env-file PATH` | | per-tenant credentials (template format) |
| `--env-file PATH` | | optional settings; repeatable |
| `--scan-ids IDS` / `--scan-ids-file PATH\|-` | | `.txt` (one per line, `#` comments), `.csv` (`scan_id`/`scanId` or first column), `.json`, `-` = stdin. UUIDs validated, de-duplicated |
| `--from-manifest DIR` | | Target tenant-only mode |
| `--scan-types` | original engines | optional; ignored by `--download-only` |
| `--download-only`, `--output-dir`, `--layout flat\|by-project`, `--no-save-zips`, `--overwrite`, `--min-free-gb 5`, `--compact-manifest` | | |
| `--source-/--target-` `base-url`, `iam-url`, `tenant`, `api-key` | env/JWT | |
| `--download-workers` | 4 (8 download-only) | |
| `--upload-workers` / `--start-workers` | 4 / 2 | |
| `--source-max-concurrency` / `--target-max-concurrency` | 8 / 8 | |
| `--metadata-batch` | 50 | max 50 |
| `--memory-zip-max-mb` / `--memory-budget-mb` | 256 / 2048 | larger or over-budget zips spill to disk |
| `--temp-dir`, `--max-zip-mb 0`, `--verify-zip` | | `0` = unlimited |
| `--multipart-threshold-mb` | 0 (off) | experimental, see checklist |
| `--transfer-timeout` | 900 | seconds |
| `--queue-check-every / --queue-max / --queue-pause-seconds / --queue-count` | 100 / 500 / 300 / queued | |
| `--preserve-order` / `--no-preserve-order` | on | |
| `--retry-failed`, `--ignore-duplicates`, `--yes-ignore-duplicates`, `--verify-engines` | | |
| `--state-db` | `./replicator-state.sqlite` | |
| `--log-dir` / `--log-file` / `--audit-file` / `--report` | `./logs` | |
| `--no-ui`, `--quiet`, `--debug`, `--dry-run`, `--allow-same-tenant`, `--force-tenant-defaults`, `--yes` | | |

`--dry-run` makes no downloads and no Target tenant writes, and creates no files except logs. It prints the plan
(scan types and the `config` array, counts to start/duplicates/unavailable, projects to create).
Write modes ask for confirmation unless `--yes`; non-interactive runs need `--yes`.

**Exit codes:** `0` all done or skipped; `2` finished with failures; `1` fatal (config, env file, scan types,
auth, preflight, disk, or run-level `apisec` rejection); `130` interrupted.

## Reading the outputs

* **Text log** (`<log-dir>/replicator-<mode>-<run_id>.log`): one line per state transition; rotates at 20 MB × 10.
* **Audit** (`....audit.jsonl`): one JSON object per event: `run_start`, `dedupe_hit`, `download_complete`,
  `zip_saved`, `project_created`, `upload_complete`, `scan_started`, `scan_start_ambiguous`,
  `scan_start_confirmed`, `queue_check`, `queue_pause`, `queue_resume`, `disk_low`, `job_failed`, `run_end`, ...
  `jq 'select(.event=="job_failed")' *.audit.jsonl`
* **Report** (`....csv`): `source_scan_id, project_name, branch, scan_types, status, error_code, zip_bytes,
  zip_sha256, zip_path, t2_project_id, t2_project_created, t2_scan_id, attempts`.
* API keys, tokens, env-file contents and the query string of pre-signed URLs are never logged (host + path only).

Common `error_code`s: `source_scan_not_found`, `source_unavailable` (archive aged out), `no_source_permission`,
`download_failed`, `bad_zip`, `too_large`, `file_exists`, `project_failed`, `upload_failed`, `start_failed`,
`start_ambiguous`, `scan_type_rejected`, `manifest_zip_missing`, `manifest_zip_corrupt`, `not_in_manifest`.

## Known API traps (handled)

* `GET /api/scans` filters by **`project-id`**; unknown params like `projectId` are silently ignored.
* `totalCount` on filtered scan queries can be tenant-wide: rows are counted instead; tag values are re-checked client-side.
* `/api/scans` sorts oldest-first by default: `sort` is always explicit when "latest" matters.
* Repostore redirects and the upload PUT only receive the bearer token when the URL host equals the tenant's own host.
* `POST /api/scans` and `POST /api/projects` are not idempotent: never blindly retried (confirm first; only 429 is retried).
* Pre-signed URLs expire: fresh ones on every retry; upload URLs are not held across a queue pause.
* Write endpoints use `Content-Type: application/json; version=1.0`.
* User-facing `iac`/`api` map to API `kics`/`apisec` in exactly one place (`src/utils/scan_types.py`).

Known limit: if a scan-start POST is ambiguous in Replicate mode the zip is already released, so the retry
re-uses the same upload URL; in from-manifest mode a fresh upload is made.

## Verify on a live tenant before the first big run

1. `"apisec"` is accepted in `config[].type` on Target tenant, and whether API Security runs when `sast` is not selected (upgrade the warning to an error if not).
2. A scan started with a subset (e.g. `sast,sca`) runs only those engines (`GET /api/scans/{id}` → `engines`; or use `--verify-engines`).
3. Target tenant's upload size limit (set `--max-zip-mb` to match).
4. The multipart upload completion response (`--multipart-threshold-mb` is off by default; the code expects a `url`/`uploadUrl`/`location` field in the completion response and fails the job otherwise).
5. `GET /api/scans/summary` status keys (`Queued` spelling/case; matched case-insensitively).
6. The tag-filter query (`tags-keys` / `tags-values`) narrows results as expected.
7. Whether `HEAD /api/repostore/scans/{id}` returns `Content-Length` (used for dry-run size estimates).
8. Pilot:
   1. `--download-only --dry-run`, then `--download-only` on 5 scans; open the zips.
   2. Replicate `--dry-run --scan-types ...`, then a live run on the same 5 scans.
   3. Compare branch / project / engines in the Target tenant UI.

## Layout

```
main.py                      CLI, mode/config validation, run wiring
src/model.py                 modes, states, error codes, ScanJob
src/utils/                   config (env files, JWT), scan_types, auth, http (TenantClient), state, audit, manifest, ui
src/operations/              inputs, preflight, pipeline (+queue gate, sequencer), tenant1, tenant2, context
tests/                       fake two-tenant HTTP layer + unit/flow/e2e tests
```
