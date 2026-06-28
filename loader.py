import os
import sys
from dataclasses import dataclass, field
from enum import Enum

# Graceful dependency handling with informative errors
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[!] Error: 'pyelftools' is required. Install it using: pip install pyelftools", file=sys.stderr)
    sys.exit(1)

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM64,
        CS_ARCH_ARM,
        CS_ARCH_X86,
        CS_MODE_ARM,
        CS_MODE_THUMB,
        CS_MODE_64
    )
except ImportError:
    print("[!] Error: 'capstone' is required. Install it using: pip install capstone", file=sys.stderr)
    sys.exit(1)


class Severity(Enum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"

    def weight(self) -> int:
        if self == Severity.CRITICAL:
            return 4
        elif self == Severity.HIGH:
            return 3
        elif self == Severity.SUSPICIOUS:
            return 2
        return 1


@dataclass
class Finding:
    rule: str          # Rule name
    severity: Severity
    title: str         # Short descriptive title of the finding
    details: dict[str, str] = None # Aligned detail key-value pairs (optional)
    reason: str = None # Factual reason why this is suspicious or malicious (optional)
    filepath: str = None # Path of the file containing the finding (optional)


@dataclass
class KernelModule:
    path: str
    arch: str                      # "arm64", "arm", "x86_64"
    elf: ELFFile                   # pyelftools ELFFile handle
    raw: bytes
    modinfo: dict[str, str]        # Parsed key-value pairs from .modinfo
    imported_symbols: list[str]    # Undefined / global external symbols
    exported_symbols: list[str]    # Globally defined symbols in the module
    all_symbols: list[str]         # Combined list of all available symbols
    sections: list[str]            # Names of present ELF sections
    functions: list[dict]          # List of: {"name": str, "offset": int, "size": int, "disasm": list[dict]}
    relocations: dict[tuple[int, int], str]


def load_module(path: str) -> KernelModule:
    """
    Reads the given filepath, parses the ELF structure, validates format,
    extracts symbols, metadata, and performs Capstone disassembly on all
    valid functions.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: '{path}'")

    try:
        with open(path, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        raise ValueError(f"Failed to read file '{path}': {e}")

    try:
        from io import BytesIO
        elf = ELFFile(BytesIO(raw_data))
    except Exception as e:
        raise ValueError(f"Invalid ELF binary format: {e}")

    try:
        # 1. Validate ELF properties
        if elf.header['e_type'] != 'ET_REL':
            raise ValueError(
                f"Invalid file type: {elf.header['e_type']}. "
                "koaudit only supports relocatable Linux kernel modules (ET_REL)."
            )

        has_module_link_section = False
        for section in elf.iter_sections():
            if section.name == '.gnu.linkonce.this_module':
                has_module_link_section = True
                break

        if not has_module_link_section:
            raise ValueError(
                "File is an unlinked ELF object (.o), not a fully linked Linux kernel module (.ko)."
            )

        e_machine = elf.header['e_machine']
        if e_machine == 'EM_AARCH64':
            arch = "arm64"
            cs_arch = CS_ARCH_ARM64
            cs_mode = CS_MODE_ARM
        elif e_machine == 'EM_ARM':
            arch = "arm"
            cs_arch = CS_ARCH_ARM
            cs_mode = CS_MODE_THUMB
        elif e_machine in ('EM_X86_64', 'EM_AMD64'):
            arch = "x86_64"
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_64
        else:
            raise ValueError(
                f"Unsupported architecture machine code: {e_machine}. "
                "Supported architectures are arm64 (AArch64), arm (ARM), and x86_64 (AMD64)."
            )

        # Instantiate Capstone handler once to reuse for performance
        try:
            cs_handle = Cs(cs_arch, cs_mode)
        except Exception:
            cs_handle = None

        # 2. Extract section names
        sections = []
        for section in elf.iter_sections():
            sections.append(section.name)

        # 3. Parse .modinfo keys and values
        modinfo = {}
        modinfo_sec = elf.get_section_by_name('.modinfo')
        if modinfo_sec:
            try:
                data = modinfo_sec.data()
                raw_strings = data.split(b'\x00')
                for raw_str in raw_strings:
                    if b'=' in raw_str:
                        try:
                            k, v = raw_str.decode('utf-8', errors='ignore').split('=', 1)
                            modinfo[k] = v
                        except Exception:
                            pass
            except Exception:
                pass

        # 4. Parse symbols (.symtab)
        imported_symbols = []
        exported_symbols = []
        all_symbols = []

        symtab = elf.get_section_by_name('.symtab')
        if symtab:
            for sym in symtab.iter_symbols():
                name = sym.name
                if not name:
                    continue
                all_symbols.append(name)

                bind = sym.entry['st_info']['bind']
                shndx = sym.entry['st_shndx']

                if bind == 'STB_GLOBAL':
                    if shndx == 'SHN_UNDEF':
                        imported_symbols.append(name)
                    elif isinstance(shndx, int):
                        exported_symbols.append(name)

        # 4b. Parse relocations
        relocations = {}
        try:
            for section in elf.iter_sections():
                if section.header['sh_type'] in ('SHT_REL', 'SHT_RELA'):
                    target_sec_idx = section.header['sh_info']
                    symtab_sec_idx = section.header['sh_link']
                    symtab_sec = elf.get_section(symtab_sec_idx)
                    if not symtab_sec:
                        continue
                    for rel in section.iter_relocations():
                        offset = rel['r_offset']
                        sym_idx = rel['r_info_sym']
                        if sym_idx < symtab_sec.num_symbols():
                            sym = symtab_sec.get_symbol(sym_idx)
                            if sym and sym.name:
                                relocations[(target_sec_idx, offset)] = sym.name
        except Exception:
            pass

        # 5. Extract and disassemble function symbols
        functions = []
        if symtab:
            for sym in symtab.iter_symbols():
                if sym.entry['st_info']['type'] == 'STT_FUNC' and sym.entry['st_size'] > 0:
                    shndx = sym.entry['st_shndx']
                    if isinstance(shndx, int):
                        try:
                            sec = elf.get_section(shndx)
                            sec_data = sec.data()
                            offset = sym.entry['st_value']
                            size = sym.entry['st_size']
                            
                            if arch == "arm":
                                is_thumb = (offset % 2 == 1)
                                func_offset = offset - 1 if is_thumb else offset
                            else:
                                is_thumb = False
                                func_offset = offset

                            # Bounds checking
                            if func_offset < 0 or func_offset + size > len(sec_data):
                                continue

                            func_bytes = sec_data[func_offset : func_offset + size]
                            
                            disasm_list = []
                            try:
                                if arch == "arm":
                                    current_mode = CS_MODE_THUMB if is_thumb else CS_MODE_ARM
                                    md = Cs(CS_ARCH_ARM, current_mode)
                                else:
                                    md = cs_handle
                                
                                if md:
                                    for insn in md.disasm(func_bytes, func_offset):
                                        disasm_list.append({
                                            "addr": insn.address,
                                            "mnemonic": insn.mnemonic,
                                            "op_str": insn.op_str,
                                            "bytes": insn.bytes
                                        })
                            except Exception:
                                pass

                            functions.append({
                                "name": sym.name,
                                "offset": func_offset,
                                "size": size,
                                "sec_idx": shndx,
                                "disasm": disasm_list
                            })
                        except Exception:
                            pass

        return KernelModule(
            path=path,
            arch=arch,
            elf=elf,
            raw=raw_data,
            modinfo=modinfo,
            imported_symbols=imported_symbols,
            exported_symbols=exported_symbols,
            all_symbols=all_symbols,
            sections=sections,
            functions=functions,
            relocations=relocations
        )
    except Exception as e:
        raise ValueError(f"Failed to parse kernel module structure: {e}")
