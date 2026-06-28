# Contributing to koaudit

First off, thank you for considering contributing to `koaudit`! It's people like you who make open-source security tools better and more accessible.

## Project Philosophy
`koaudit` is designed to be a traditional Unix-like security utility: fast, deterministic, lightweight, and easy to audit. We do not use AI/ML or cloud services. All analysis must remain local and static.

## How to Contribute

### Reporting Bugs
- Ensure the bug is reproducible against the latest main branch.
- Include the exact command run, shell environment, and (if possible) a safe copy or description of the target module causing the issue.

### Implementing New Heuristic Rules
1. All rules must subclass the `Rule` base class located in [rules.py](rules.py).
2. Keep findings strictly factual. Do not use overly dramatic language or security buzzwords.
3. Every finding must declare a clean `title`, optional `details` dictionary, and a factual `reason`.
4. Register your new rule class in `ALL_RULES` inside `rules.py`.

### Code Review Checklist
- Check for duplicate code or redundant iterations.
- Run the full test suite locally:
  ```bash
  python3 -m unittest tests/test_koaudit.py
  ```
- Make sure code remains compatible with Python 3.8+ and runs without crashing on malformed or stripped ELF inputs.
