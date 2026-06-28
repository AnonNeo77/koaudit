import json
import os
from loader import Finding, Severity

# Minimal ANSI formatting
BOLD = "\033[1m"
RESET = "\033[0m"

RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREEN = "\033[92m"
DIM = "\033[2m"

def text_report(path: str, findings: list[Finding], elapsed: float = 0.0) -> str:
    """
    Generates a minimal and factual text-based security audit report.
    """
    # 1. Determine status
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_suspicious_or_high = any(f.severity in (Severity.HIGH, Severity.SUSPICIOUS) for f in findings)

    if has_critical:
        status_text = f"{RED}Malicious{RESET}"
    elif has_suspicious_or_high:
        status_text = f"{YELLOW}Suspicious{RESET}"
    else:
        status_text = f"{GREEN}Clean{RESET}"

    lines = []
    lines.append(f"{BOLD}KOAUDIT{RESET}")
    lines.append(f"Target: {os.path.basename(path) if hasattr(os, 'path') else path}")
    lines.append(f"Status: {status_text}")
    lines.append("")
    
    # 2. Render Findings Section
    if findings:
        lines.append("Findings")
        lines.append("──────────────────────────────────")
        
        findings_by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.SUSPICIOUS: [],
            Severity.INFO: []
        }
        for f in findings:
            findings_by_severity[f.severity].append(f)

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.SUSPICIOUS, Severity.INFO]
        for sev in severity_order:
            sev_findings = findings_by_severity[sev]
            if not sev_findings:
                continue

            # Severity Header
            if sev == Severity.CRITICAL:
                sev_color = RED
            elif sev == Severity.HIGH:
                sev_color = YELLOW
            elif sev == Severity.SUSPICIOUS:
                sev_color = CYAN
            else:
                sev_color = DIM

            lines.append(f"{sev_color}[{sev.value.upper()}]{RESET}")
            for f in sev_findings:
                lines.append(f"• {f.title}")
                if f.details:
                    for k, v in f.details.items():
                        lines.append(f"  - {k}: {v}")
                if f.reason:
                    lines.append(f"  - Reason: {f.reason}")
            lines.append("")

    # 3. Render Summary Section
    lines.append("Summary")
    lines.append("──────────────────────────────────")
    
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_suspicious_or_high = any(f.severity in (Severity.HIGH, Severity.SUSPICIOUS) for f in findings)

    detected_behaviors = []
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.SUSPICIOUS):
            # Clean up the bullet text (strip trailing dot for consistent presentation)
            clean_title = f.title.rstrip(".")
            if clean_title not in detected_behaviors:
                detected_behaviors.append(clean_title)

    if detected_behaviors:
        lines.append("Detected:")
        for behavior in detected_behaviors:
            lines.append(f"• {behavior}")
        lines.append("")

    lines.append("Recommendation:")
    if has_critical or has_suspicious_or_high:
        lines.append("Review the source before loading this module.")
    else:
        lines.append("No suspicious behaviors were detected by the current rule set.")
        lines.append("Static analysis cannot guarantee that a module is safe.")
    lines.append("")

    lines.append("──────────────────────────────────")
    lines.append("Scan completed successfully.")
    lines.append(f"Findings: {len(findings)}")
    lines.append(f"Elapsed: {elapsed:.2f} s")

    return "\n".join(lines)


def json_report(path: str, findings: list[Finding]) -> str:
    """
    Serializes findings to machine-readable JSON structure.
    """
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_suspicious_or_high = any(f.severity in (Severity.HIGH, Severity.SUSPICIOUS) for f in findings)

    if has_critical:
        status = "Malicious"
    elif has_suspicious_or_high:
        status = "Suspicious"
    else:
        status = "Clean"

    data = {
        "target": path,
        "status": status,
        "summary": {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "suspicious": sum(1 for f in findings if f.severity == Severity.SUSPICIOUS),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
            "total": len(findings)
        },
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity.value,
                "title": f.title,
                "details": f.details,
                "reason": f.reason
            }
            for f in findings
        ]
    }
    return json.dumps(data, indent=2)


def html_report(path: str, findings: list[Finding]) -> str:
    """
    Generates a clean HTML report dashboard.
    """
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    suspicious_count = sum(1 for f in findings if f.severity == Severity.SUSPICIOUS)
    info_count = sum(1 for f in findings if f.severity == Severity.INFO)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_suspicious_or_high = any(f.severity in (Severity.HIGH, Severity.SUSPICIOUS) for f in findings)

    if has_critical:
        status = "Malicious"
        status_color = "text-red-400 border-red-500/30 bg-red-500/10"
    elif has_suspicious_or_high:
        status = "Suspicious"
        status_color = "text-amber-400 border-amber-500/30 bg-amber-500/10"
    else:
        status = "Clean"
        status_color = "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"

    sorted_findings = sorted(
        findings,
        key=lambda x: (
            0 if x.severity == Severity.CRITICAL
            else 1 if x.severity == Severity.HIGH
            else 2 if x.severity == Severity.SUSPICIOUS
            else 3
        )
    )

    finding_rows_html = ""
    for i, f in enumerate(sorted_findings, 1):
        if f.severity == Severity.CRITICAL:
            badge_class = "bg-red-500/15 text-red-400 border-red-500/30"
        elif f.severity == Severity.HIGH:
            badge_class = "bg-amber-500/15 text-amber-400 border-amber-500/30"
        elif f.severity == Severity.SUSPICIOUS:
            badge_class = "bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
        else:
            badge_class = "bg-slate-500/15 text-slate-400 border-slate-500/30"

        details_html = ""
        if f.details:
            details_html += "<ul class='list-disc list-inside space-y-1 mb-2 font-mono text-[11px] text-slate-300'>"
            for k, v in f.details.items():
                details_html += f"<li><strong>{k}:</strong> {v}</li>"
            details_html += "</ul>"
            
        reason_html = f"<div class='text-slate-400 text-xs mt-1'><span class='text-slate-500 font-bold'>Reason:</span> {f.reason}</div>" if f.reason else ""

        finding_rows_html += f"""
        <tr data-severity="{f.severity.value}" class="border-b border-slate-800/40 hover:bg-slate-900/5 transition-colors">
            <td class="p-4 text-center font-mono text-xs text-slate-500 font-bold">{i}</td>
            <td class="p-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border {badge_class}">
                    {f.severity.value.upper()}
                </span>
            </td>
            <td class="p-4 font-semibold text-slate-200 text-xs">{f.rule}</td>
            <td class="p-4 text-xs font-semibold text-slate-200">{f.title}</td>
            <td class="p-4">
                {details_html}
                {reason_html}
            </td>
        </tr>
        """

    if not findings:
        finding_rows_html = """
        <tr>
            <td colspan="5" class="p-12 text-center text-emerald-400 font-semibold bg-emerald-950/10">
                🎉 No suspicious behavioral heuristics matched.
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>koaudit Analysis Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Inter', 'sans-serif'],
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{
            background-color: #080d1a;
            color: #f8fafc;
        }}
        .glass {{
            background: rgba(15, 23, 42, 0.45);
            backdrop-filter: blur(12px);
        }}
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans antialiased">
    <header class="border-b border-slate-800 bg-slate-950/60 backdrop-blur py-5 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 flex justify-between items-center">
            <div>
                <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                    🛡️ <span class="text-slate-200">koaudit</span> Analysis
                </h1>
            </div>
            <div class="text-xs font-mono text-slate-400 bg-slate-900/60 border border-slate-800 p-2 rounded-lg max-w-md truncate">
                Target: {path}
            </div>
        </div>
    </header>

    <main class="flex-grow max-w-7xl mx-auto w-full px-6 py-8">
        <!-- Status Panel -->
        <div class="glass border border-slate-800 rounded-2xl p-6 mb-8 flex justify-between items-center {status_color}">
            <div>
                <span class="text-xs font-bold uppercase tracking-wider opacity-60">Analysis Verdict</span>
                <h2 class="text-2xl font-black mt-1">{status}</h2>
            </div>
            <div class="text-xs font-mono opacity-80">
                {critical_count} Critical | {high_count} High | {suspicious_count} Suspicious | {info_count} Info
            </div>
        </div>

        <!-- Findings Table -->
        <div class="glass border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-500 font-bold text-xs uppercase bg-slate-950/20">
                            <th class="p-4 w-12 text-center">#</th>
                            <th class="p-4 w-28">Severity</th>
                            <th class="p-4 w-36">Rule</th>
                            <th class="p-4 w-72">Finding</th>
                            <th class="p-4">Evidence / Reason</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/40 text-slate-300">
                        {finding_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <footer class="border-t border-slate-900 bg-slate-950 py-5 mt-16 text-center text-xs text-slate-500 font-mono">
        koaudit static analysis engine.
    </footer>
</body>
</html>
"""
    return html_content
