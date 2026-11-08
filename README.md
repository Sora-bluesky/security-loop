[English](README.md) | [日本語](README.ja.md)

# security-loop

security-loop checks software on a Windows PC and inventory received from a VPS.
It matches installed versions against OSV and runtime security advisories.
It also checks CISA's Known Exploited Vulnerabilities (KEV) catalog and release feeds.
This is a personal tool, shared as-is. Review its results before acting on them.

## What the loop does

`scan.py` collects Python environments, npm packages and supported lockfiles, runtime versions,
Windows apps, services, listening ports, and container/VM names.
It reads VPS package and listener inventory sent to the PC.
The coverage map links these assets to advisory, release, update, or manual checks.
Container names and image tags do not prove that their contents were checked.

Results distinguish a match, no match, and a check that could not be completed.
Saved state tracks new findings, changed affected ranges, and newly uncovered assets.
An exit code of 0 does not mean that every asset was checked or is safe.
Read `unverified` in `out/findings.json`.

Each normal scan also rechecks the claims in `impact-items.json`.
Evidence records its source, observation time, collector, and scope.
Missing evidence is unverified. A value that differs from the previous value, or from the expectation on the first check, is reported as a change.
If the value then stays unchanged but still contradicts the expectation, it is unverified.
Changed claim hashes invalidate prior review.
`report_build.py` turns these saved checks into a daily JSON report document.
It does not publish the report or create a Word document.

The public snapshot contains code, synthetic examples, and synthetic test fixtures.
Private settings, inventories, reports, and development history stay outside that snapshot.
The publication gate checks paths and content. It cannot identify every private value.

## Requirements

- Windows and Python 3.14. The Python code uses the standard library.
- Windows PowerShell for inventory commands. Scans can run installed tools to read versions.
- GitHub CLI (`gh`) for GitHub advisories and releases. Configure its access separately.
- npm, Node.js, and other runtime commands for the corresponding local checks.
- Optional: `patchwait` on `PATH` for bundled Node.js and distrust checks.
  The current integration expects a caller-supplied `g3.pem` distrust bundle at the repository root.
  This snapshot does not supply that certificate file. Leave the integration disabled until configured.
- Optional: ScanMux, Node.js, Git, and a local OSV database for repository dependency checks.
- For VPS inventory, see [vps/README.md](vps/README.md). The collector runs on Linux.

Normal scans contact advisory and release services. Selftests use fixed responses and do not need network access.
No scheduler for the Windows scan is installed by this repository.

## Setup

Open PowerShell in the cloned repository. Copy the examples, then replace the synthetic values:

```powershell
Copy-Item scan-config.example.json scan-config.json
Copy-Item coverage-map.example.json coverage-map.json
Copy-Item assets-manual.example.json assets-manual.json
Copy-Item local-config.example.json local-config.json
Copy-Item impact-items.example.json impact-items.json
Copy-Item watch-prompt.example.md x-watch-prompt.md
```

Copy only when the destination does not already contain settings you need.
`local-config.json` is optional. Remove example overrides you do not intend to use.
Set `impact-items.json` to `{"items": []}` if you have no claims to track.
The example claims demonstrate the schema; they are not findings about your machine.

When `scan-config.json`, `coverage-map.json`, `assets-manual.json`, or `x-watch-prompt.md` is absent, the loader uses its named sibling example.
Other custom `--config` paths do not fall back to examples.
It prints one notice per selected example to stderr. An existing invalid real file is not replaced by an example.
`--config PATH` selects a scan config. Its sibling `local-config.json` supplies the `scan` overlay.
Objects merge recursively; arrays and scalar values replace the base values.
Relative `python_roots` and `npm_lock_roots` resolve from the working directory.
Relative `coverage_map` and `vps_inventory_glob` paths resolve from the script directory.
Use absolute local paths for ScanMux's `node`, `entry`, `config`, and repository paths.

The examples use fake repositories, commands, and `example.test` URLs.
They describe the format; they do not provide useful live monitoring until you configure them.

### Scan configuration

| Key | Meaning |
|---|---|
| `python_roots` | Directories searched for Python environments. |
| `npm_lock_roots` | Directories searched for supported npm lockfiles. |
| `exclude_path_parts` | Case-insensitive substrings matched against full directory paths during those searches; `venv` also excludes `myvenv`. |
| `watch_releases` | GitHub `owner/repo` names whose latest releases are checked. |
| `tag_repos` | Repositories to check through tags instead of release objects. |
| `kev_keywords` | Explicit KEV keywords. Product names also supply filtered derived keywords. |
| `patchtheplanet_url` | Disclosure page to parse; empty disables this check. |
| `patchwait.enabled` | Run the optional patchwait integration. |
| `patchwait.node_roots`, `patchwait.node_excludes` | Bundled Node.js search roots and exclusions passed to patchwait. |
| `patchwait.roots_keystore` | Optional Java keystore path. An empty value omits it. |
| `patchwait.timeout_sec` | Timeout for each patchwait command. |
| `scanmux.enabled` | Run the optional ScanMux integration. |
| `scanmux.node`, `scanmux.entry`, `scanmux.config` | Absolute paths to Node.js, the ScanMux entry script, and its config. |
| `scanmux.repos`, `scanmux.timeout_sec` | Absolute repository paths and timeout per ScanMux command. |
| `osv_batch_size` | Number of package/version queries per OSV batch. |
| `osv_detail_ttl_hours` | Cache lifetime for PyPI/npm OSV detail records, and for distro records when modification data is unavailable. |
| `coverage_map` | Coverage-map JSON path. |
| `vps_hosts` | Accepted inventory host names. Use the same names as the collector. |
| `vps_inventory_glob` | Pattern for received VPS inventory files. |
| `vps_inventory_filename` | Name used for the saved inventory and incoming-file handling. |
| `http_timeout_sec`, `user_agent` | HTTP request timeout and User-Agent. |
| `runtime_advisories[].repo` | GitHub repository supplying runtime advisories. |
| `runtime_advisories[].version_cmd` | Command argument array used to read the installed runtime version. |
| `advisory_fixed_overrides` | GHSA-keyed objects with `fixed` version arrays for otherwise unparseable ranges. `note` and `source` document the choice. |

Optional scan keys include `vps_private_networks` (networks treated as private for VPS listeners),
`coverage_extra_rules` (additional coverage entries), and `impact_release_codenames`
(release-to-codename mappings for impact checks).
The PC does not log in to the VPS. VPS package and listener inventory older than 13 hours is unverified.
Impact checks may use an older retained snapshot and show its collection time.

### Coverage and manual assets

`coverage-map.json` is an array of rules:

| Key | Meaning |
|---|---|
| `match` | Case-insensitive regular expression for an asset name. Docker matches use the image repository name. |
| `product` | Product display name used to build the watch list. |
| `kinds` | Asset kinds: `apps`, `services`, `listening`, `containers_vms`, `manual`, `python_envs`, `npm_global`, `npm_locks`, `runtimes`, `vps_packages`, or `vps_listening`. |
| `routes` | Objects containing `type` and `ref`. Types are `osv`, `runtime_advisory`, `github_advisories`, `winget`, `release`, `kev`, `x_watch`, and `manual`. |
| `routes[].ref` | Package name for OSV, `owner/repo` for GitHub routes, or a product/check reference for other routes. |
| `path_match` | Optional executable-path regex for services and listeners. |
| `publisher_match` | Optional full regex for an Appx publisher's CN. Both the name and publisher must match. |
| `advisory_sources` | Optional accepted version sources: `registry` and/or `appx`. Defaults to registry for GitHub app advisories. |
| `advisory_package` | Optional package-name override when matching a GitHub app advisory. |
| `note` | Human explanation of the rule. |

A route records a checking path, not a promise that the path succeeded.
Service and listener app routes need a matching app and a successful check from this scan.
`winget` checks for updates; it is not a vulnerability verdict.
`manual` and `x_watch` routes require follow-up outside the scanner.

`assets-manual.json` is an array of objects with `product`, `where` (location), and `note`.
It adds assets that automatic inventory cannot collect.
The prompt template must contain `{{PRODUCTS}}`.
The scanner writes the filled template to `out/x-watch-prompt.md`; it does not run an AI watch agent.
`xseen.py` can classify or mark separately collected X-watch JSONL using a local seen list.
`source_health.py` diagnoses saved collection failures. Neither reads the scan example configs.

### Optional integration settings

`local-config.json` has three optional sections: `scan`, `scanmux`, and `vps`.
`scan` overrides the scan keys above. `scanmux` overlays the config passed to ScanMux.
The JSON at `scanmux.config` is merged with the `scanmux` section of a `local-config.json` beside that file, then passed to the installed ScanMux.
Refer to that version's documentation for the meaning of its keys and configuration requirements.
The VPS section uses `inventory_filename` and `taildrop_target` (the PC's Taildrop destination).
Copy only the VPS section to the collector, as described in its guide.

## Run

```powershell
py -3.14 -I -B scan.py --scan-id example-scan
py -3.14 -I -B scan.py --cve CVE-2099-10001
py -3.14 -I -B report_build.py --scan-id example-scan --items impact-items.json --findings out/findings.json --base none --output out/daily-report.json
```

Use the ID from the scan that produced the findings when building the report.
Omit `--scan-id` on a scan to generate an ID. Replace `--base none` with a previous daily JSON report to preserve its other sections.
The output directory must exist; a completed scan creates `out/`.
`scan.py --baseline` records ordinary findings as known. It still reports impact changes.

| Exit code | Normal scan | `--cve` |
|---|---|---|
| 0 | No new findings within the completed checks. | No affected local version found; unverified items may remain. |
| 10 | New findings or impact changes. | An affected local version was found. |
| 2 | Failure or required-check failure when there are no new findings; new findings take precedence and return 10. | The identifier could not be retrieved or the command failed. |

Results and cache/state files are local. Do not publish them.
`report_build.py` exits 2 for file/JSON errors, invalid report structure, or a scan-ID mismatch.
Item-level validation problems are rendered with diagnostics and can return 0.
The VPS collector has separate installation and removal instructions in [vps/](vps/README.md).

## Selftests

Run from the repository root. No real configuration, host inventory, or social posts are needed.
The publication selftest creates disposable local Git repositories and uses a test substitute for gitleaks.
It tests gate behavior, not the real secret detector.

```powershell
py -3.14 -I -B scan.py --selftest
py -3.14 -I -B scan.py --selftest-runtime
py -3.14 -I -B scan.py --selftest-ptp
py -3.14 -I -B scan.py --selftest-patchwait
py -3.14 -I -B scan.py --selftest-scanmux
py -3.14 -I -B scan.py --selftest-coverage
py -3.14 -I -B scan.py --selftest-xwatch
py -3.14 -I -B scan.py --selftest-vps
py -3.14 -I -B scan.py --selftest-impact
py -3.14 -I -B source_health.py --selftest
py -3.14 -I -B report_build.py --selftest
py -3.14 -I -B tools/publish_check.py selftest
```

## Publication gate

[tools/README.md](tools/README.md) describes the maintainer's publication workflow.
`tools/publish-allowlist.txt` selects snapshot paths. Internal-path rules exclude private files even if allowlisted.
The gate checks configured private markers, machine-user names, user-folder paths, IP addresses,
and commit identities. Publication also requires gitleaks.
Use local guard and marker files; never put private marker values into tracked files.

```powershell
py -3.14 -I -B tools/publish_check.py --markers markers.txt --guard guard.json all
```

`all` audits existing Git history. It does not check unstaged edits or certify a public snapshot.
`publish SOURCE` checks the selected committed snapshot and creates a separate public ref without pushing it.
Inspect its file list and content before publication. A fresh clone needs none of this setup to run the selftests.

## License

[MIT](LICENSE)

## agent_secrets.py

Offline checker for literal credentials saved in Claude permission rules, settings
`env` values, and MCP server strings. It reports path, location, kind, value length,
and Git tracked/ignored status; it never reports credential values or their hashes.
Locations use indices for server, environment, and header names, for example
`mcpServers[0].headers[1]`, so dictionary keys cannot expose credentials.
It uses only the Python standard library and local Git commands.

```powershell
py -3.14 -I -B agent_secrets.py --root .
py -3.14 -I -B agent_secrets.py --file .claude/settings.local.json --json
py -3.14 -I -B agent_secrets.py --root . --history
py -3.14 -I -B agent_secrets.py --root . --exclude "archive*" --exclude "group/old-*" --history
py -3.14 -I -B agent_secrets.py --selftest
```

Repeat `--root` or `--file` to scan multiple locations. There is no default root.
Root discovery includes `.mcp.json` and `.claude/settings.local.json` / `settings.json`
in directories up to five levels below each root (the root itself is level zero).
It skips `node_modules`, `.git`, `.venv`, `venv`, `__pycache__`, and directory links.
Repeat `--exclude GLOB` to skip directories by name or root-relative path using
`fnmatch` (case-insensitive on Windows; `/` separates path components in examples).
Matches are skipped before directory access, including matching roots and repositories;
history findings under matching directories are also excluded. Each pattern gets a
notice with its count of excluded directories encountered during discovery (including zero).
Explicit `--file` targets bypass discovery. Invalid JSON is scanned line by line
and findings are marked `unparsed`. Unreadable targets are errors.
An unreadable or vanished directory records its path, failing step, and OS error
class/errno; discovery continues through the other directories. Git errors include
the command step and exit code. Unknown Git status is `null` in JSON (`unknown` in text).
An unusable `.git` that Git identifies as "not a git repository" is skipped with a
`skipped invalid git dir` notice. Other Git failures remain errors, including
`dubious ownership`; the checker never changes Git's ownership safety settings.

`--history` also checks complete target files at up to 200 matching commits per
repository using the same structured scanner, and reports truncation per repository.
Repeated findings are grouped by path, location, kind, and length; `oldest_commit`
and `newest_commit` retain the observed endpoints and their remote containment
flags (`oldest_remote`, `newest_remote`). The existing `commit` and `remote` fields
refer to the newest occurrence. Endpoints cover only the scanned commits.
It discovers repositories (including `.git` files) up to five levels below each root, so a plain folder of repositories works.
Each repository's history covers the target names at any depth, including files
deleted from the working tree or now ignored. Explicit `--file` history stays scoped
to those files unless that repository is also discovered through `--root`.
Commit identifiers and remote containment refer to local Git data; nothing is fetched.
JSON output includes `files_scanned`, `findings`, `errors`, and `notices`.
Exit codes: **0** no findings, **10** findings, **2** usage/read/Git error (errors take precedence).
References and placeholders are skipped; generic assignments require six characters.
Provider-shaped values are reported except inside angle-bracket placeholders
or `op://` references; fixed-length GitHub token shapes require 36 alphanumeric
characters after the prefix. Uppercase values containing digits are not placeholders.
Supported forms include attached `curl -uuser:pass`, `Authorization: token`, and
`api-key` headers. This is a heuristic check, not proof
that settings contain no credentials. It does not modify the scanned files.
