# Architecture

SorobanShield is a local, synchronous static-analysis CLI for Rust/Soroban projects. The CLI selects rules and presentation options; the core discovers and parses project files, runs the rules and builds a report; the rules crate contains the individual checks. Scanning does not compile or execute the target project.

## Scan flow

```text
sorobanshield scan [PATH] [--recursive] [--format text|json|sarif]
    |
    +--> CLI loads optional sorobanshield.toml (or --config)
    |      -> validate exclusions, disabled rule IDs and fail-on threshold
    +--> CLI loads optional --baseline
    +--> select enabled rules from active_rules()
    |
    v
project.rs: Project::discover_with(PATH, exclusions)
    OR --recursive: discover_projects(PATH, exclusions)
                    -> discover each Soroban project beneath PATH
    |
    v
engine.rs: scan_project for each discovered project
    -> read and parse Cargo.toml manifests and Rust source files (syn)
    -> testcode.rs identifies test-only files
    -> Rule::check(SourceUnit) on non-test-only files
    -> Rule::check_project(ProjectUnit) across all parsed files
    -> Rule::check_manifest(ManifestUnit) on parsed manifests
    -> suppress.rs applies inline sorobanshield-ignore directives
    -> sort findings; with --recursive, prefix project paths and merge results
    |
    v
CLI applies optional baseline.rs fingerprints to remaining findings
    -> report.rs: Report (findings, scan errors, suppression details, summary)
    -> output: text | json | sarif
    -> exit status (or --write-baseline to save current findings)
```

Without `--recursive`, `PATH` must be a Soroban project root containing `Cargo.toml`. With `--recursive`, `discover_projects` searches beneath `PATH` for Soroban projects; a discovered project (including a workspace with Soroban members) is scanned as one project rather than scanning its nested members again. Findings and errors in a recursive scan are prefixed with the project path, relative to the requested root. Discovery ignores known build/dependency directories and respects configured path exclusions. See [CLI reference](cli-reference.md) and [configuration](configuration.md).

## Crates

| Crate | Responsibility |
| --- | --- |
| [`sorobanshield-core`](../crates/sorobanshield-core/src/lib.rs) | Project and recursive discovery, parsing and scan orchestration, rule interfaces, findings, test-only detection, config, inline suppressions, baselines, and report generation (terminal, JSON and SARIF). |
| [`sorobanshield-rules`](../crates/sorobanshield-rules/src/lib.rs) | Implementations of SS-001 through SS-006; shared rule utilities in `common.rs`; `active_rules()`, `catalog()` and `find_rule()`. |
| [`sorobanshield-cli`](../crates/sorobanshield-cli/src/main.rs) | `clap` commands and flags, configuration/baseline loading, rule selection, output-format choice and exit status; [CLI integration tests](../crates/sorobanshield-cli/tests/cli.rs). |

### Core source modules

Every Rust module declared by [`sorobanshield-core/src/lib.rs`](../crates/sorobanshield-core/src/lib.rs) is listed here:

| Module | Responsibility |
| --- | --- |
| [`lib.rs`](../crates/sorobanshield-core/src/lib.rs) | Declares the core modules and re-exports the public API. |
| [`baseline.rs`](../crates/sorobanshield-core/src/baseline.rs) | Loads, validates, writes and applies JSON baselines using rule ID, file and message fingerprints (not line numbers). |
| [`config.rs`](../crates/sorobanshield-core/src/config.rs) | Parses/validates TOML scan exclusions, severity threshold and disabled rule IDs. |
| [`engine.rs`](../crates/sorobanshield-core/src/engine.rs) | Parses source files, invokes the three rule hooks, applies inline suppressions, records scan errors and coordinates single/recursive scans. |
| [`finding.rs`](../crates/sorobanshield-core/src/finding.rs) | Defines findings, severity/confidence levels and deterministic finding sort keys. |
| [`project.rs`](../crates/sorobanshield-core/src/project.rs) | Discovers project sources and manifests, recognizes Soroban dependencies, skips excluded paths and finds projects recursively. |
| [`report.rs`](../crates/sorobanshield-core/src/report.rs) | Assembles report metadata, counts and errors; renders terminal, JSON and SARIF 2.1.0 output. |
| [`rule.rs`](../crates/sorobanshield-core/src/rule.rs) | Defines `Rule`/`RuleMeta`, input units for file/project/manifest checks and normalized relative paths. |
| [`suppress.rs`](../crates/sorobanshield-core/src/suppress.rs) | Parses `sorobanshield-ignore` comments, suppresses matching findings and reports unused suppression IDs. |
| [`testcode.rs`](../crates/sorobanshield-core/src/testcode.rs) | Recognizes test-only source files from test directories and `#[cfg(test)]` module/file attributes, including discovered child modules. |

## How rules receive input

The [`Rule` trait](../crates/sorobanshield-core/src/rule.rs) exposes three optional hooks; each defaults to returning no findings. The engine calls each hook on every enabled rule, but only the hooks implemented by that rule produce findings.

| Hook | Input | Rules currently implementing it |
| --- | --- | --- |
| `check(&SourceUnit)` | One parsed Rust file, excluding test-only files. | **SS-002**, **SS-003**, **SS-004**. |
| `check_project(&ProjectUnit)` | All parsed Rust files with a `test_only` path set for cross-file analysis. | **SS-001** (cross-file storage-write and authorization path checks), **SS-005** (state-transition test suggestions). |
| `check_manifest(&ManifestUnit)` | A parsed `Cargo.toml`, with its root/relative path and access to the project root for sibling-file checks. | **SS-006** (toolchain diagnostics). |

Test-only files remain available to project-level rules (including SS-005), but are excluded from `check` calls. `testcode.rs` detects files in `tests/`, files marked with an inner `#![cfg(test)]` attribute and modules declared through `#[cfg(test)]` (including their out-of-line children); it does not resolve custom `#[path = ...]` module paths. Individual rules can also inspect inline `#[cfg(test)]` modules in the AST.

Rule metadata (`RuleMeta`) is supplied by each implementation. [`active_rules()`](../crates/sorobanshield-rules/src/lib.rs) registers the six implemented checks, and `catalog()` derives its ordered metadata from those active rules. `rules list` and `rules explain` use this catalog; planned checks are not part of the active registry. Source locations use `proc-macro2` spans with `span-locations`.

## Configuration, suppressions and baselines

- **Configuration:** The CLI loads `--config FILE` if specified, otherwise `PATH/sorobanshield.toml` when present. `Config` validates `[scan].exclude` (relative path prefixes), `[scan].fail_on` and `[rules].disable`. `--fail-on` overrides the configured severity threshold; the default is `low`. Disabled rules do not run. See [configuration](configuration.md).
- **Inline suppressions:** The engine reads `// sorobanshield-ignore: SS-001 -- reason` directives while parsing Rust sources, then filters matching findings by rule, file and target line (or approximate following block). It keeps a record of suppressed findings and unmatched directives. Findings without source line numbers cannot match a line-based directive. See [reports](reports.md).
- **Baseline:** After the engine's inline suppression pass, the CLI can load `--baseline FILE` and hide findings whose `rule_id|file|message` fingerprint is already recorded. It reports unmatched baseline entries. `--write-baseline FILE` writes the current findings instead of applying a baseline, and only succeeds when the scan has no operational errors. See [reports](reports.md).

Scanning the target project is read-only and makes no network requests or calls to its build scripts. The explicit `--write-baseline` option is the exception: it writes the requested baseline JSON file.

## Results and failure behavior

- Files are visited in deterministic order, finding lists are sorted by file/line/rule, and output uses project-relative paths with `/` separators. JSON severity totals use ordered keys.
- `Report` retains findings, parse/read errors, inline suppression records and a summary. The CLI can render **text**, **JSON** or **SARIF 2.1.0** for `scan`; `rules list/explain` support text and JSON only.
- A failed discovery or unreadable/malformed source is **not a clean scan** (exit code **3**). Invalid CLI usage, config or baseline input returns **2**. A completed scan returns **1** if a remaining finding meets the active severity threshold, otherwise **0** (or **0** after a successful `--write-baseline`). A scan with zero findings does not prove the contract is secure.

## Where do I change X?

| Goal | Start here |
| --- | --- |
| Add or change a detection rule | [`sorobanshield-rules/src/ss00*.rs`](../crates/sorobanshield-rules/src/lib.rs), [`common.rs`](../crates/sorobanshield-rules/src/common.rs), [`active_rules()`](../crates/sorobanshield-rules/src/lib.rs) and the [rule-authoring guide](rule-authoring.md) |
| Add a new scan output format | [`Report` rendering](../crates/sorobanshield-core/src/report.rs) and [CLI `ScanFormat`/dispatch](../crates/sorobanshield-cli/src/main.rs) |
| Add or change a CLI flag or exit code | [`sorobanshield-cli/src/main.rs`](../crates/sorobanshield-cli/src/main.rs) and [CLI tests](../crates/sorobanshield-cli/tests/cli.rs) |
| Change project discovery or recursive scanning | [`project.rs`](../crates/sorobanshield-core/src/project.rs) and [`engine.rs`](../crates/sorobanshield-core/src/engine.rs) |
| Change test-only file handling | [`testcode.rs`](../crates/sorobanshield-core/src/testcode.rs) and the `ProjectUnit::test_only` field in [`rule.rs`](../crates/sorobanshield-core/src/rule.rs) |
| Change configuration, inline suppression or baseline behavior | [`config.rs`](../crates/sorobanshield-core/src/config.rs), [`suppress.rs`](../crates/sorobanshield-core/src/suppress.rs), [`baseline.rs`](../crates/sorobanshield-core/src/baseline.rs) and CLI integration |
| Change finding fields or report layout | [`finding.rs`](../crates/sorobanshield-core/src/finding.rs) and [`report.rs`](../crates/sorobanshield-core/src/report.rs) |
| Update docs shown on the website | Edit [`docs/`](./) directly; the website imports these pages rather than keeping a separate copy. |

The [Rust integration suite](../crates/sorobanshield-cli/tests/cli.rs) includes `relative_links_in_repository_markdown_resolve`, which checks links in repository Markdown files, including this page.
