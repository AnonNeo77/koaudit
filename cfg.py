import re
from loader import KernelModule

class CallGraph:
    """
    Constructs a control flow / call graph from relocations and branch instructions.
    Enables deep static sequence and reachability tracing with lookup caching.
    """
    def __init__(self, module: KernelModule):
        self.graph: dict[str, set[str]] = {}
        for f in module.functions:
            self.graph[f["name"]] = set()
        self._build(module)
        self._chain_cache = {}
        self._init_cache = {}
        self._any_path_cache = {}

    def _build(self, module: KernelModule):
        for func in module.functions:
            caller = func["name"]
            sec_idx = func.get("sec_idx", -1)

            for insn in func.get("disasm", []):
                is_call = False
                mnemonic = insn["mnemonic"].lower()
                
                if module.arch == "x86_64":
                    if mnemonic in ("call", "jmp"):
                        is_call = True
                elif module.arch in ("arm64", "arm"):
                    if mnemonic in ("bl", "blr", "blx", "b"):
                        is_call = True

                if not is_call:
                    continue

                target_symbol = None
                
                # Scan relocations corresponding to the instruction's byte offset
                if sec_idx != -1:
                    for off in range(insn["addr"], insn["addr"] + len(insn.get("bytes", b""))):
                        if (sec_idx, off) in module.relocations:
                            target_symbol = module.relocations[(sec_idx, off)]
                            break

                # Fallback: Parse hex values in operand string
                if not target_symbol:
                    hex_matches = re.findall(r'0x[0-9a-fA-F]+', insn["op_str"])
                    for hex_val in hex_matches:
                        try:
                            val = int(hex_val, 16)
                            for f in module.functions:
                                if f["offset"] == val:
                                    target_symbol = f["name"]
                                    break
                        except ValueError:
                            pass
                        if target_symbol:
                            break

                if target_symbol:
                    self.graph[caller].add(target_symbol)

    def calls(self, caller: str, callee: str) -> bool:
        """Returns True if caller directly calls callee."""
        return callee in self.graph.get(caller, set())

    def chain_exists(self, start: str, *targets: str) -> bool:
        """
        Returns True if a path exists from any node matching 'start' (substring)
        sequentially traversing all targets (substring matches) using BFS.
        """
        cache_key = (start, targets)
        if cache_key in self._chain_cache:
            return self._chain_cache[cache_key]
        
        res = self._chain_exists_uncached(start, *targets)
        self._chain_cache[cache_key] = res
        return res

    def _chain_exists_uncached(self, start: str, *targets: str) -> bool:
        if not targets:
            return True

        current_nodes = {node for node in self.graph if start in node}
        if not current_nodes:
            return False

        for target in targets:
            next_nodes = set()
            for src in current_nodes:
                visited = set()
                queue = [src]
                while queue:
                    curr = queue.pop(0)
                    if curr in visited:
                        continue
                    visited.add(curr)
                    
                    neighbors = self.graph.get(curr, set())
                    for n in neighbors:
                        if target in n:
                            next_nodes.add(n)
                        else:
                            queue.append(n)
            if not next_nodes:
                return False
            current_nodes = next_nodes
        return True

    def any_path_to(self, target: str) -> list[str]:
        """Returns all functions that eventually branch to target."""
        if target in self._any_path_cache:
            return self._any_path_cache[target]
            
        res = self._any_path_to_uncached(target)
        self._any_path_cache[target] = res
        return res

    def _any_path_to_uncached(self, target: str) -> list[str]:
        callers = []
        for node in self.graph:
            if node == target:
                continue
            visited = set()
            queue = [node]
            reachable = False
            while queue:
                curr = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                neighbors = self.graph.get(curr, set())
                if target in neighbors:
                    reachable = True
                    break
                for n in neighbors:
                    queue.append(n)
            if reachable:
                callers.append(node)
        return callers

    def reachable_from_init(self, target: str) -> bool:
        """Checks if a target is reachable from functions associated with module initialization."""
        if target in self._init_cache:
            return self._init_cache[target]
            
        res = self._reachable_from_init_uncached(target)
        self._init_cache[target] = res
        return res

    def _reachable_from_init_uncached(self, target: str) -> bool:
        init_nodes = [node for node in self.graph if "init" in node.lower()]
        for start in init_nodes:
            visited = set()
            queue = [start]
            while queue:
                curr = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                if curr == target or target in self.graph.get(curr, set()):
                    return True
                for n in self.graph.get(curr, set()):
                    queue.append(n)
        return False
