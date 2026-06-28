#!/usr/bin/env python3
import sys
import argparse
import os

from loader import load_module, Severity
from rules import ALL_RULES, RULE_MAP
from report import text_report, json_report, html_report



def parse_args():
    parser = argparse.ArgumentParser(
        description="koaudit: Static analysis tool to scan and flag suspicious behavior in Linux kernel modules (.ko)."
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to the kernel module (.ko) file, or a directory to scan recursively."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report in JSON format."
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Output report in HTML format."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output logging."
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version info and exit."
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to a specific file (prints to stdout if omitted)."
    )
    parser.add_argument(
        "-r", "--rules",
        help="Comma-separated list of specific rules to execute (e.g. syscall_hook,inline_hook)."
    )
    return parser.parse_args()


def deduplicate_findings(findings: list) -> list:
    """
    Groups findings by (rule, title, reason) and merges alias function names
    to ensure each unique behavior is reported only once, sorting and deduplicating
    details like function names and numeric offsets.
    """
    merged = {}
    for f in findings:
        key = (f.rule, f.title, f.reason)
        if key not in merged:
            details_copy = dict(f.details) if f.details else None
            if details_copy:
                if "Function" in details_copy:
                    funcs = [x.strip() for x in details_copy["Function"].split(",") if x.strip()]
                    details_copy["Function"] = ", ".join(sorted(list(set(funcs))))
                if "Offset" in details_copy:
                    details_copy["Offsets"] = details_copy["Offset"]
                    del details_copy["Offset"]
                if "Offsets" in details_copy:
                    offs = [x.strip() for x in details_copy["Offsets"].split(",") if x.strip()]
                    def get_int_val(x):
                        try:
                            return int(x, 16) if x.lower().startswith("0x") else int(x)
                        except ValueError:
                            return 0
                    sorted_offs = sorted(list(set(offs)), key=get_int_val)
                    details_copy["Offsets"] = ", ".join(sorted_offs)
                
            from loader import Finding
            merged[key] = Finding(
                rule=f.rule,
                severity=f.severity,
                title=f.title,
                details=details_copy,
                reason=f.reason,
                filepath=f.filepath
            )
        else:
            existing = merged[key]
            if f.details:
                if existing.details is None:
                    existing.details = {}
                for k, v in f.details.items():
                    is_offset_key = k in ("Offset", "Offsets")
                    
                    if k == "Function":
                        orig_val = existing.details.get("Function", "")
                        existing_funcs = [x.strip() for x in orig_val.split(",") if x.strip()]
                        new_funcs = [x.strip() for x in v.split(",") if x.strip()]
                        combined = sorted(list(set(existing_funcs + new_funcs)))
                        existing.details["Function"] = ", ".join(combined)
                    elif is_offset_key:
                        orig_val = existing.details.get("Offsets") or existing.details.get("Offset") or ""
                        existing_offsets = [x.strip() for x in orig_val.split(",") if x.strip()]
                        new_offsets = [x.strip() for x in v.split(",") if x.strip()]
                        all_offsets = list(set(existing_offsets + new_offsets))
                        
                        def get_int_val(x):
                            try:
                                return int(x, 16) if x.lower().startswith("0x") else int(x)
                            except ValueError:
                                return 0
                        
                        sorted_offsets = sorted(all_offsets, key=get_int_val)
                        if "Offset" in existing.details:
                            del existing.details["Offset"]
                        existing.details["Offsets"] = ", ".join(sorted_offsets)
                    else:
                        if k in existing.details:
                            if existing.details[k] != v:
                                existing.details[k] = f"{existing.details[k]}, {v}"
                        else:
                            existing.details[k] = v
    return list(merged.values())


def audit_file(filepath: str, selected_rules: list) -> list:
    """Loads a single kernel module and runs configured analysis rules on it."""
    module = load_module(filepath)
    findings = []
    for r in selected_rules:
        rule_findings = r.analyze(module)
        for f in rule_findings:
            f.filepath = filepath
        findings.extend(rule_findings)
    return deduplicate_findings(findings)


def main():
    # Ensure stdout and stderr use UTF-8 encoding (especially on Windows terminals)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    args = parse_args()

    if args.version:
        print("koaudit version 1.1.0")
        sys.exit(0)

    if not args.path:
        print("[-] Error: target file path is required. Use --help for usage details.", file=sys.stderr)
        sys.exit(1)

    # 1. Determine which rules to execute
    if args.rules:
        target_rule_names = [name.strip() for name in args.rules.split(",")]
        selected_rules = []
        for name in target_rule_names:
            if name in RULE_MAP:
                selected_rules.append(RULE_MAP[name])
            else:
                print(f"[-] Warning: Rule '{name}' does not exist. Skipping.", file=sys.stderr)
    else:
        selected_rules = ALL_RULES

    if not selected_rules:
        print("[-] Error: No rules selected for analysis.", file=sys.stderr)
        sys.exit(1)

    # 2. Collect files to scan (supports target file or directory search)
    scanned_files = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for file in files:
                if file.endswith(".ko"):
                    scanned_files.append(os.path.join(root, file))
    else:
        scanned_files.append(args.path)

    if not scanned_files:
        print(f"[-] Error: No valid .ko files found to audit at '{args.path}'", file=sys.stderr)
        sys.exit(1)

    # 3. Analyze targets
    import time
    start_time = time.perf_counter()
    all_findings = []
    file_reports = []
    for filepath in scanned_files:
        if args.verbose or len(scanned_files) > 1:
            print(f"[*] Scanning: {filepath}")
        try:
            findings = audit_file(filepath, selected_rules)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        all_findings.extend(findings)
        
        has_crit = any(f.severity == Severity.CRITICAL for f in findings)
        has_susp_or_high = any(f.severity in (Severity.HIGH, Severity.SUSPICIOUS) for f in findings)
        if has_crit:
            label = "MALICIOUS"
            color = "\033[91m"  # Red
        elif has_susp_or_high:
            label = "SUSPICIOUS"
            color = "\033[93m"  # Yellow
        else:
            label = "CLEAN"
            color = "\033[92m"  # Green
        file_reports.append((filepath, findings, label, color))

    # 4. Print consolidated summary table for multiple files
    if len(scanned_files) > 1 and not args.json and not args.html and not args.output:
        print("\n" + "=" * 80)
        print(f"\033[1mScan Summary Table ({len(scanned_files)} files processed)\033[0m")
        print("-" * 80)
        print(f"{'File Name':<45} | {'Findings':<10} | {'Status':<15}")
        print("-" * 80)
        for filepath, findings, label, color in file_reports:
            fname = os.path.basename(filepath)
            if len(fname) > 45:
                fname = fname[:42] + "..."
            print(f"{fname:<45} | {len(findings):<10} | {color}{label}\033[0m")
        print("=" * 80 + "\n")

    # 5. Generate Reports
    # Set fallback target label if multiple files were consolidated
    target_label = args.path if len(scanned_files) > 1 else scanned_files[0]
    elapsed = time.perf_counter() - start_time

    if args.html:
        out_content = html_report(target_label, all_findings)
    elif args.json:
        out_content = json_report(target_label, all_findings)
    else:
        out_content = text_report(target_label, all_findings, elapsed)

    # 6. Output management
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_content)
            print(f"[+] Scan completed successfully. Report written to '{args.output}'")
        except Exception as e:
            print(f"[-] Error writing report to file '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(out_content)

    # Exit with code 1 if critical or high issues were found (useful for integration)
    serious_findings = sum(1 for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    if serious_findings > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
