# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-06-28
### Added
- Linked kernel module checking (`.gnu.linkonce.this_module` verification) to distinguish `.ko` from unlinked compiler objects (`.o`).
- Robust format checks in the parsing loader protecting execution from corrupted or truncated ELF files.
- Memoization cache within the `CallGraph` class to accelerate reachability traversals.
- Direct `--json` and `--html` options alongside `--version` for Unix-like tool usage.
- Automated GitHub Actions configurations for testing and release package compilation.
- LICENSE and CONTRIBUTING guides.

### Changed
- Refactored `Finding` models to focus entirely on concise, factual details, removing scoring systems and subjective wording.
- Redesigned CLI summaries to output unique behaviors and status verdicts cleanly.
