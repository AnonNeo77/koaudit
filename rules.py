import os
from loader import KernelModule, Finding, Severity

class Rule:
    name: str = ""
    description: str = ""

    def analyze(self, module: KernelModule) -> list[Finding]:
        try:
            return self._analyze(module)
        except Exception:
            return []

    def _analyze(self, module: KernelModule) -> list[Finding]:
        raise NotImplementedError

    def get_call_graph(self, module: KernelModule):
        if not hasattr(module, "_call_graph"):
            from cfg import CallGraph
            module._call_graph = CallGraph(module)
        return module._call_graph


class MetadataRule(Rule):
    name = "metadata"
    description = "Checks module metadata for structural and naming anomalies."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []

        if "author" not in module.modinfo:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.INFO,
                title="Missing module author."
            ))

        if "description" not in module.modinfo:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.INFO,
                title="Missing module description."
            ))

        base_name = os.path.splitext(os.path.basename(module.path))[0]
        if "name" in module.modinfo and module.modinfo["name"] != base_name:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.SUSPICIOUS,
                title="Module name differs from filename.",
                details={
                    "Internal": module.modinfo["name"],
                    "File": f"{base_name}.ko"
                }
            ))

        return findings


class SyscallHookRule(Rule):
    name = "syscall_hook"
    description = "Checks for syscall table imports and write protection overrides."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []

        if "sys_call_table" in module.imported_symbols:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.CRITICAL,
                title="Direct sys_call_table import",
                details={"Symbol": "sys_call_table"},
                reason="Bypasses symbol lookup protections to read/write system calls."
            ))

        if module.arch == "arm64":
            for func in module.functions:
                for ins in func["disasm"]:
                    combined_instr = f"{ins['mnemonic']} {ins['op_str']}".lower()
                    if "sctlr_el1" in combined_instr:
                        findings.append(Finding(
                            rule=self.name,
                            severity=Severity.CRITICAL,
                            title="Write protection bypass detected",
                            details={
                                "Function": func["name"],
                                "Offset": hex(ins["addr"]),
                                "Instruction": combined_instr
                            },
                            reason="Disables write protection to modify write-protected page mappings."
                        ))

        if module.arch == "x86_64":
            for func in module.functions:
                for ins in func["disasm"]:
                    if ins["mnemonic"].lower().startswith("mov") and "cr0" in ins["op_str"].lower():
                        findings.append(Finding(
                            rule=self.name,
                            severity=Severity.CRITICAL,
                            title="Write protection bypass detected",
                            details={
                                "Function": func["name"],
                                "Offset": hex(ins["addr"]),
                                "Instruction": f"{ins['mnemonic']} {ins['op_str']}"
                            },
                            reason="Disables write protection to modify write-protected page mappings."
                        ))

        # Dynamic sys_call_table query
        rodata_sec = module.elf.get_section_by_name('.rodata')
        if rodata_sec and "kallsyms_lookup_name" in module.imported_symbols:
            data = rodata_sec.data()
            if b"sys_call_table" in data:
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.CRITICAL,
                    title="Dynamic sys_call_table resolution",
                    details={
                        "Imports": "kallsyms_lookup_name",
                        "Target": "sys_call_table"
                    },
                    reason="Dynamically queries the system call table pointer."
                ))

        return findings


class HookFrameworkRule(Rule):
    name = "hook_framework"
    description = "Checks for dynamic function hooking framework usages."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        hook_apis = [
            "register_ftrace_function", "register_kprobe",
            "register_kretprobe", "register_kprobes",
            "register_jprobe", "kprobe_lookup_name"
        ]
        for api in hook_apis:
            if api in module.imported_symbols:
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.HIGH,
                    title="Dynamic function tracing hook detected",
                    details={"Function": api},
                    reason="Registers callback functions to intercept or trace execution of kernel routines."
                ))
        return findings


class SelfHidingRule(Rule):
    name = "self_hiding"
    description = "Checks for module self-hiding behaviors."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        cg = self.get_call_graph(module)
        for api in ["list_del", "kobject_del"]:
            if cg.reachable_from_init(api):
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.CRITICAL,
                    title="Self-hiding behavior in initialization",
                    details={"Function": f"{api} in init path"},
                    reason="Attempts to unlink itself from modules or sysfs list structures."
                ))
        return findings


class ProcHidingRule(Rule):
    name = "proc_hiding"
    description = "Checks for directory list filtering and file system iteration overrides."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        cg = self.get_call_graph(module)
        
        # Identify custom directory iteration/fill callbacks
        iter_funcs = []
        for func in module.functions:
            fname = func["name"].lower()
            if "iterate" in fname or "filldir" in fname:
                iter_funcs.append(func["name"])
                
        for fn in iter_funcs:
            # Check if iterate function performs string comparisons to filter outputs
            for cmp_api in ["strcmp", "strncmp", "memcmp"]:
                if cg.chain_exists(fn, cmp_api):
                    findings.append(Finding(
                        rule=self.name,
                        severity=Severity.HIGH,
                        title="Directory iteration filtering detected",
                        details={"Function": fn, "Filter": cmp_api},
                        reason="Filters directory entry listings to hide specific filenames or process directories."
                    ))
                    break # Avoid duplicate warnings per function
        return findings


class CredAbuseRule(Rule):
    name = "cred_abuse"
    description = "Checks for privilege escalation and credentials updates."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        cg = self.get_call_graph(module)
        
        # Check standard credentials modification APIs
        cred_apis = ["prepare_creds", "commit_creds", "prepare_kernel_cred", "override_creds", "revert_creds"]
        found_apis = [api for api in cred_apis if api in module.imported_symbols]
        
        if found_apis:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.HIGH,
                title="Credentials manipulation APIs imported",
                details={"Symbols": ", ".join(sorted(found_apis))},
                reason="Prepares or commits credentials blocks to change running process capabilities."
            ))

        # Trace CallGraph from user-land interface targets to credential committer
        user_gateways = ["ioctl", "write", "read"]
        commit_targets = ["commit_creds", "override_creds"]
        
        for gate in user_gateways:
            gate_nodes = [node for node in cg.graph if gate in node.lower()]
            for gate_node in gate_nodes:
                for commit in commit_targets:
                    if cg.chain_exists(gate_node, commit):
                        findings.append(Finding(
                            rule=self.name,
                            severity=Severity.CRITICAL,
                            title="Privilege escalation control flow",
                            details={"Path": f"{gate_node} -> {commit}"},
                            reason="Exposes process privilege escalation capability to userland interfaces."
                        ))
        return findings


class BackdoorInterfaceRule(Rule):
    name = "backdoor_interface"
    description = "Checks for creation of backdoor interfaces."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        backdoor_apis = ["proc_create", "debugfs_create_file", "debugfs_create_dir"]
        found_apis = [api for api in backdoor_apis if api in module.imported_symbols]
        if found_apis:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.SUSPICIOUS,
                title="User-space control gateway",
                details={"Symbols": ", ".join(sorted(found_apis))},
                reason="Registers file entries enabling userland configuration/control signals."
            ))
        return findings


class NetfilterHookRule(Rule):
    name = "netfilter_hook"
    description = "Checks for Netfilter hooks that intercept packets."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        netfilter_apis = [
            "nf_register_net_hook", "nf_register_net_hooks",
            "nf_register_hook", "nf_register_hooks"
        ]
        for api in netfilter_apis:
            if api in module.imported_symbols:
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.HIGH,
                    title="Network packet interceptor hook",
                    details={"Import": api},
                    reason="Registers callbacks to intercept, drop, or modify network packets."
                ))
        return findings


class SuspiciousCallbackRule(Rule):
    name = "suspicious_callbacks"
    description = "Checks for notifier callback registrations monitor system state changes."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        apis = [
            "register_reboot_notifier", "register_keyboard_notifier",
            "register_netdevice_notifier", "register_module_notifier"
        ]
        for api in apis:
            if api in module.imported_symbols:
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="Suspicious callback notifier registered",
                    details={"Callback": api},
                    reason="Registers notification hooks to trigger module code on system events."
                ))
        return findings


class StringIntelRule(Rule):
    name = "string_intel"
    description = "Scans read-only sections for sensitive configuration paths."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        suspicious_strings = [
            (b"/bin/sh", "Execution of shell commands"),
            (b"/etc/passwd", "Accessing password files"),
            (b"/etc/shadow", "Accessing shadow password files"),
        ]

        rodata_sec = module.elf.get_section_by_name('.rodata')
        if rodata_sec:
            data = rodata_sec.data()
            for pattern, desc in suspicious_strings:
                if pattern in data:
                    findings.append(Finding(
                        rule=self.name,
                        severity=Severity.HIGH,
                        title="Embedded sensitive file path reference",
                        details={"Path": pattern.decode('utf-8', errors='ignore')},
                        reason="References restricted system directories or configuration targets."
                    ))
        return findings


class EntropyRule(Rule):
    name = "entropy"
    description = "Checks for entropy obfuscation markers."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        for sec_name in module.sections:
            sec = module.elf.get_section_by_name(sec_name)
            if not sec:
                continue
            data = sec.data()
            if not data:
                continue
            
            import math
            entropy = 0.0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            
            if entropy > 7.2:
                findings.append(Finding(
                    rule=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="High entropy section detected",
                    details={
                        "Section": sec_name,
                        "Entropy": f"{entropy:.2f}"
                    },
                    reason="Indicates section contains packed or compressed data payloads."
                ))
        return findings


class IoctlAnalysisRule(Rule):
    name = "ioctl_analysis"
    description = "Scans for custom IOCTL unlocked/compat registration and handlers."

    def _analyze(self, module: KernelModule) -> list[Finding]:
        findings = []
        ioctl_funcs = []
        for func in module.functions:
            fname = func["name"].lower()
            if "ioctl" in fname and not fname.startswith("__pfx_"):
                ioctl_funcs.append(func["name"])
        
        for fn in ioctl_funcs:
            findings.append(Finding(
                rule=self.name,
                severity=Severity.HIGH,
                title="Custom IOCTL interface detected",
                details={"Function": fn},
                reason="User-space control interface."
            ))
        return findings


ALL_RULES: list[Rule] = [
    MetadataRule(),
    SyscallHookRule(),
    HookFrameworkRule(),
    SelfHidingRule(),
    ProcHidingRule(),
    CredAbuseRule(),
    BackdoorInterfaceRule(),
    NetfilterHookRule(),
    SuspiciousCallbackRule(),
    StringIntelRule(),
    EntropyRule(),
    IoctlAnalysisRule(),
]

RULE_MAP: dict[str, Rule] = {r.name: r for r in ALL_RULES}
