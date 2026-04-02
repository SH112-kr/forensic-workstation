"""Ghidra headless connector via pyhidra — binary analysis without GUI."""

from __future__ import annotations

import os
from typing import Any

from connectors.base import BaseConnector

# Suspicious Win32 APIs commonly used by malware
SUSPICIOUS_APIS = {
    # Process injection
    "VirtualAlloc": "T1055 - Process Injection: memory allocation",
    "VirtualAllocEx": "T1055 - Process Injection: remote memory allocation",
    "VirtualProtect": "T1055 - Process Injection: memory protection change",
    "VirtualProtectEx": "T1055 - Process Injection: remote memory protection change",
    "WriteProcessMemory": "T1055 - Process Injection: write to remote process",
    "CreateRemoteThread": "T1055 - Process Injection: remote thread creation",
    "CreateRemoteThreadEx": "T1055 - Process Injection: remote thread creation",
    "NtCreateThreadEx": "T1055 - Process Injection: NT remote thread",
    "QueueUserAPC": "T1055 - Process Injection: APC injection",
    "NtQueueApcThread": "T1055 - Process Injection: APC injection",
    "RtlCreateUserThread": "T1055 - Process Injection: user thread creation",
    "SetThreadContext": "T1055 - Process Injection: thread context manipulation",

    # Process/thread manipulation
    "OpenProcess": "T1055 - Process access for injection or dumping",
    "CreateProcessA": "T1106 - Native API: process creation",
    "CreateProcessW": "T1106 - Native API: process creation",
    "CreateProcessAsUserA": "T1134 - Access Token Manipulation",
    "CreateProcessAsUserW": "T1134 - Access Token Manipulation",
    "WinExec": "T1106 - Legacy process execution",
    "ShellExecuteA": "T1106 - Shell execution",
    "ShellExecuteW": "T1106 - Shell execution",
    "ShellExecuteExA": "T1106 - Shell execution",
    "ShellExecuteExW": "T1106 - Shell execution",

    # Credential access
    "CredEnumerateA": "T1555 - Credential enumeration",
    "CredEnumerateW": "T1555 - Credential enumeration",
    "LsaEnumerateLogonSessions": "T1003 - Logon session enumeration",
    "SamQueryInformationUser": "T1003 - SAM query",

    # Persistence / Registry
    "RegSetValueExA": "T1547 - Registry modification (potential persistence)",
    "RegSetValueExW": "T1547 - Registry modification (potential persistence)",
    "RegCreateKeyExA": "T1547 - Registry key creation",
    "RegCreateKeyExW": "T1547 - Registry key creation",

    # File operations
    "DeleteFileA": "T1070 - Indicator Removal: file deletion",
    "DeleteFileW": "T1070 - Indicator Removal: file deletion",
    "MoveFileA": "T1036 - Masquerading: file move",
    "MoveFileW": "T1036 - Masquerading: file move",

    # Network
    "InternetOpenA": "T1071 - Application Layer Protocol: HTTP",
    "InternetOpenW": "T1071 - Application Layer Protocol: HTTP",
    "InternetOpenUrlA": "T1071 - URL connection",
    "InternetOpenUrlW": "T1071 - URL connection",
    "HttpOpenRequestA": "T1071 - HTTP request",
    "HttpOpenRequestW": "T1071 - HTTP request",
    "URLDownloadToFileA": "T1105 - Ingress Tool Transfer",
    "URLDownloadToFileW": "T1105 - Ingress Tool Transfer",
    "WSAStartup": "T1071 - Winsock initialization",
    "connect": "T1071 - Socket connection",
    "send": "T1041 - Exfiltration Over C2 Channel",
    "recv": "T1071 - Data reception",
    "socket": "T1071 - Socket creation",
    "getaddrinfo": "T1071 - DNS resolution",

    # Crypto
    "CryptEncrypt": "T1486 - Data Encrypted for Impact (potential ransomware)",
    "CryptDecrypt": "T1140 - Deobfuscation/Decryption",
    "CryptCreateHash": "T1027 - Obfuscated Files: hashing",
    "CryptAcquireContextA": "T1027 - Crypto context acquisition",
    "CryptAcquireContextW": "T1027 - Crypto context acquisition",
    "BCryptEncrypt": "T1486 - BCrypt encryption (potential ransomware)",
    "BCryptDecrypt": "T1140 - BCrypt decryption",

    # Defense evasion
    "IsDebuggerPresent": "T1622 - Debugger Evasion",
    "CheckRemoteDebuggerPresent": "T1622 - Debugger Evasion",
    "NtQueryInformationProcess": "T1622 - Anti-analysis check",
    "GetTickCount": "T1497 - Virtualization/Sandbox Evasion: timing check",
    "Sleep": "T1497 - Virtualization/Sandbox Evasion: delayed execution",
    "NtDelayExecution": "T1497 - Delayed execution",

    # Service manipulation
    "CreateServiceA": "T1543 - Create or Modify System Process: service",
    "CreateServiceW": "T1543 - Create or Modify System Process: service",
    "StartServiceA": "T1569 - System Services: service execution",
    "StartServiceW": "T1569 - System Services: service execution",
    "OpenSCManagerA": "T1543 - Service Control Manager access",
    "OpenSCManagerW": "T1543 - Service Control Manager access",

    # DLL loading
    "LoadLibraryA": "T1129 - Shared Modules: DLL loading",
    "LoadLibraryW": "T1129 - Shared Modules: DLL loading",
    "LoadLibraryExA": "T1129 - Shared Modules: DLL loading",
    "LoadLibraryExW": "T1129 - Shared Modules: DLL loading",
    "GetProcAddress": "T1106 - Dynamic API resolution",
    "LdrLoadDll": "T1129 - NT DLL loading",
}


class GhidraConnector(BaseConnector):
    """Headless Ghidra via pyhidra for binary analysis."""

    def __init__(self) -> None:
        self._program = None
        self._flat_api = None
        self._context = None
        self._path: str = ""
        self._pyhidra_started: bool = False

    @staticmethod
    def _find_ghidra_install() -> str:
        """Auto-detect Ghidra installation directory."""
        import glob
        candidates = []
        # Common Windows install paths
        for base in [
            os.path.expandvars(r"%ProgramFiles%"),
            os.path.expandvars(r"%ProgramFiles(x86)%"),
            "C:/Tools",
            "D:/Tools",
            os.path.expanduser("~"),
            "C:/",
            "D:/",
        ]:
            candidates.extend(glob.glob(os.path.join(base, "ghidra*", "ghidraRun.bat")))
            candidates.extend(glob.glob(os.path.join(base, "Ghidra*", "ghidraRun.bat")))
        # Return the newest (highest version) match
        if candidates:
            candidates.sort(reverse=True)
            return os.path.dirname(candidates[0])
        return ""

    @staticmethod
    def _find_jdk() -> str:
        """Auto-detect JDK installation for Ghidra.

        Always returns a JDK home path if one can be found, even if java is
        on PATH.  pyhidra's LaunchSupport needs JAVA_HOME set explicitly.
        """
        import glob
        # If JAVA_HOME already set and valid, use it
        existing = os.environ.get("JAVA_HOME", "")
        if existing and os.path.isfile(os.path.join(existing, "bin", "java.exe")):
            return existing
        # Search common JDK locations on Windows
        search_roots = [
            os.path.expandvars(r"%ProgramFiles%"),
            os.path.expandvars(r"%ProgramFiles%/Java"),
            os.path.expandvars(r"%ProgramFiles%/Eclipse Adoptium"),
            "C:/Tools",
            "D:/Tools",
        ]
        for base in search_roots:
            matches = glob.glob(os.path.join(base, "jdk*", "bin", "java.exe"))
            if matches:
                matches.sort(reverse=True)
                return os.path.dirname(os.path.dirname(matches[0]))
        return ""

    def connect(self, path: str, **kwargs: Any) -> dict:
        """Import and analyze a binary file.

        Args:
            path: Path to binary file (exe, dll, sys, etc.)
        """
        import pyhidra

        if not os.path.isfile(path):
            raise FileNotFoundError(f"Binary not found: {path}")

        if not self._pyhidra_started:
            ghidra_dir = kwargs.get("ghidra_install_dir", "") or os.environ.get("GHIDRA_INSTALL_DIR", "")
            if not ghidra_dir:
                ghidra_dir = self._find_ghidra_install()
            if ghidra_dir:
                if not os.path.isdir(ghidra_dir):
                    raise FileNotFoundError(f"{ghidra_dir} does not exist")
                os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
            else:
                raise FileNotFoundError(
                    "Ghidra installation not found. Set FORENSIC_GHIDRA_INSTALL_DIR in .env, "
                    "pass ghidra_install_dir parameter, or install Ghidra in a standard location "
                    "(C:/Tools/ghidra_*, C:/Program Files/ghidra_*)."
                )
            # Auto-detect JDK if not on PATH
            jdk_home = self._find_jdk()
            if jdk_home:
                os.environ["JAVA_HOME"] = jdk_home
                java_bin = os.path.join(jdk_home, "bin")
                if java_bin not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = java_bin + os.pathsep + os.environ.get("PATH", "")
            pyhidra.start()
            self._pyhidra_started = True

        self._context = pyhidra.open_program(path)
        self._flat_api = self._context.__enter__()
        self._program = self._flat_api.getCurrentProgram()
        self._path = path

        return self._get_overview()

    def disconnect(self) -> None:
        if self._context:
            try:
                self._context.__exit__(None, None, None)
            except Exception:
                pass
            self._context = None
            self._flat_api = None
            self._program = None

    def is_connected(self) -> bool:
        return self._program is not None

    def get_metadata(self) -> dict:
        if not self._program:
            return {}
        return self._get_overview()

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        """Search strings in the binary."""
        results = self.list_strings(min_length=4, limit=1000)
        if keyword:
            kw_lower = keyword.lower()
            results = [s for s in results if kw_lower in s.get("value", "").lower()]
        return {"total": len(results), "strings": results[offset:offset + limit]}

    def get_capabilities(self) -> list[str]:
        return [
            "search", "decompile", "functions", "imports", "exports",
            "strings", "xrefs", "suspicious_apis",
        ]

    # ── Analysis Methods ──

    def _get_overview(self) -> dict:
        prog = self._program
        lang = prog.getLanguage()
        mem = prog.getMemory()
        fm = prog.getFunctionManager()

        return {
            "file": os.path.basename(self._path),
            "path": self._path,
            "format": str(prog.getExecutableFormat()),
            "language": str(lang.getLanguageID()),
            "compiler": str(prog.getCompiler()),
            "image_base": str(prog.getImageBase()),
            "memory_blocks": mem.getNumAddressRanges(),
            "function_count": fm.getFunctionCount(),
            "executable_sha256": str(prog.getExecutableSHA256()),
        }

    def list_functions(self, filter_pattern: str = "", limit: int = 100) -> list[dict]:
        """List functions with optional name filter."""
        fm = self._program.getFunctionManager()
        results = []
        for func in fm.getFunctions(True):
            name = func.getName()
            if filter_pattern and filter_pattern.lower() not in name.lower():
                continue
            results.append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "is_thunk": func.isThunk(),
                "calling_convention": str(func.getCallingConventionName()),
                "parameter_count": func.getParameterCount(),
            })
            if len(results) >= limit:
                break
        return results

    def decompile_function(self, address: str = "", name: str = "") -> dict:
        """Decompile a function to C pseudocode.

        Args:
            address: Function address (hex, e.g. "0x00401000")
            name: Function name (alternative to address)
        """
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        func = self._resolve_function(address, name)
        if func is None:
            return {"error": f"Function not found: {address or name}"}

        decomp = DecompInterface()
        decomp.openProgram(self._program)
        monitor = ConsoleTaskMonitor()
        result = decomp.decompileFunction(func, 30, monitor)

        decomp_func = result.getDecompiledFunction()
        if decomp_func is not None:
            c_code = decomp_func.getC()
        else:
            c_code = "(decompilation failed)"

        return {
            "function_name": func.getName(),
            "address": str(func.getEntryPoint()),
            "decompiled_c": c_code,
            "signature": str(func.getSignature()),
        }

    def list_imports(self) -> list[dict]:
        """List imported functions/symbols."""
        sym_table = self._program.getSymbolTable()
        results = []
        for sym in sym_table.getExternalSymbols():
            source_obj = sym.getSource()
            results.append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "namespace": str(sym.getParentNamespace()),
                "source": str(source_obj),
            })
        return results

    def list_exports(self) -> list[dict]:
        """List exported functions/symbols."""
        sym_table = self._program.getSymbolTable()
        from ghidra.program.model.symbol import SymbolType
        results = []
        for sym in sym_table.getDefinedSymbols():
            if sym.isExternalEntryPoint():
                results.append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                    "type": str(sym.getSymbolType()),
                })
        return results

    def list_strings(self, min_length: int = 4, limit: int = 500) -> list[dict]:
        """Extract defined strings from the binary."""
        from ghidra.program.model.data import StringDataInstance

        listing = self._program.getListing()
        mem = self._program.getMemory()
        results = []

        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            data_iter = listing.getDefinedData(block.getStart(), True)
            while data_iter.hasNext() and len(results) < limit:
                data = data_iter.next()
                if data.getAddress().compareTo(block.getEnd()) > 0:
                    break
                sdi = StringDataInstance.getStringDataInstance(data)
                if sdi is not None:
                    val = sdi.getStringValue()
                    if val and len(val) >= min_length:
                        results.append({
                            "address": str(data.getAddress()),
                            "value": val[:500],
                            "length": len(val),
                        })
        return results

    def get_xrefs(self, address: str) -> list[dict]:
        """Get cross-references to/from an address.

        Args:
            address: Hex address (e.g. "0x00401000")
        """
        from ghidra.program.model.symbol import RefType

        addr = self._program.getAddressFactory().getAddress(address)
        if addr is None:
            return [{"error": f"Invalid address: {address}"}]

        ref_mgr = self._program.getReferenceManager()
        results = []

        # References TO this address
        for ref in ref_mgr.getReferencesTo(addr):
            results.append({
                "direction": "to",
                "from_address": str(ref.getFromAddress()),
                "to_address": str(ref.getToAddress()),
                "type": str(ref.getReferenceType()),
            })

        # References FROM this address
        for ref in ref_mgr.getReferencesFrom(addr):
            results.append({
                "direction": "from",
                "from_address": str(ref.getFromAddress()),
                "to_address": str(ref.getToAddress()),
                "type": str(ref.getReferenceType()),
            })

        return results

    def find_suspicious_apis(self) -> dict:
        """Flag imported APIs associated with malicious behavior."""
        imports = self.list_imports()
        findings = []
        categories: dict[str, list[str]] = {}

        for imp in imports:
            api_name = imp["name"]
            if api_name in SUSPICIOUS_APIS:
                desc = SUSPICIOUS_APIS[api_name]
                technique = desc.split(" - ")[0] if " - " in desc else ""
                findings.append({
                    "api": api_name,
                    "namespace": imp["namespace"],
                    "description": desc,
                    "mitre_technique": technique,
                })
                cat = technique or "Other"
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(api_name)

        return {
            "total_suspicious": len(findings),
            "total_imports": len(imports),
            "by_technique": {k: len(v) for k, v in categories.items()},
            "findings": findings,
        }

    # ── Helpers ──

    def _resolve_function(self, address: str = "", name: str = ""):
        """Resolve a function by address or name."""
        fm = self._program.getFunctionManager()
        if address:
            addr = self._program.getAddressFactory().getAddress(address)
            if addr:
                return fm.getFunctionAt(addr)
        if name:
            for func in fm.getFunctions(True):
                if func.getName() == name:
                    return func
        return None
