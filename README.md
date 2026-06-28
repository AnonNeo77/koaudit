# 🛡️ koaudit: Linux Kernel Module Static Auditor

`koaudit` is a fast, lightweight, and deterministic static analysis tool designed to audit compiled Linux kernel modules (`.ko`) for suspicious or malicious behavior before they are loaded into kernel memory.

The tool parses ELF properties, reconstructs call graphs, and applies heuristic checks entirely locally. It follows the traditional Unix utility philosophy: fast, deterministic, and easy to audit.

---

## 🚀 Key Features

- **Robust ELF Validation**: Gracefully handles malformed, truncated, or stripped ELF headers without crashing. Automatically rejects unlinked compiler object files (`.o`).
- **Control Flow Graph Cache**: Reconstructs function branch graphs from relocations, caching reachability checks to ensure high performance on large drivers.
- **Factual Behavioral Detections**:
  - **Syscall Hooking**: CR0/SCTLR write-protection register bypasses, sys_call_table modifications, and kallsyms redirects.
  - **Evasive Hooking**: Dynamic function hooks using `ftrace`, `kprobes`, or notifier callbacks.
  - **Rootkit Backdoors**: Unlocked/compat IOCTL handlers, procfs/debugfs gateways, and Netfilter packet interceptors.
  - **Evasion Tactics**: Section entropy checks (packing/obfuscation) and unlinking self-hiding operations inside initialization routines.
- **Minimal Unix CLI**: Standard flags for format controls and verbose reporting (`--json`, `--html`, `--version`).
- **Clean Reports**: Stripped of numerical score metrics and dramatic wording; groups output logically by severity and prints a clear behavior list.

---

## 📦 Installation & Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Standalone Binaries**:
   We distribute pre-compiled standalone executables for Linux (`x86_64` and `ARM64`) on every tagged release. Check the **Releases** tab to download.

---

## 💻 Usage

```bash
# Auditing a module with default text summary to stdout
koaudit module.ko

# Output JSON report
koaudit --json module.ko

# Output HTML report
koaudit --html module.ko

# Verbose scanning details
koaudit --verbose module.ko

# Version details
koaudit --version
```

### Example Terminal Output
```
KOAUDIT
Target: antipatterns_module.ko
Status: Suspicious

Findings
──────────────────────────────────
[HIGH]
• Custom IOCTL interface detected
  - Function: ap_ioctl
  - Reason: User-space control interface.

[SUSPICIOUS]
• Module name differs from filename.
  - Internal: antipatterns
  - File: antipatterns_module.ko

Summary
──────────────────────────────────
Status: Suspicious

Detected:
• Module name differs from filename
• Custom IOCTL interface detected

Recommendation:
Review the source before loading this module.
```

---

## 🧪 Testing

Run the automated test suite locally:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## 📄 License
Distributed under the MIT License. See [LICENSE](LICENSE) for details.
