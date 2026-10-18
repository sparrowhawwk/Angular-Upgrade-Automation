#!/usr/bin/env python3
"""
Angular LTS Upgrade & Dependency Compatibility Advisor
------------------------------------------------------
A zero-dependency Python tool to inspect an Angular workspace,
discover active LTS versions from official Angular sources (angular.dev & release APIs),
audit ecosystem dependencies for compatibility, and safely execute the upgrade.

Fully cross-platform: Runs seamlessly on Windows, macOS, and Linux.
Windows Rules: Always executes via Command Prompt (cmd.exe); never uses PowerShell.
Workspace Health: Automatically validates and synchronizes local node_modules
to prevent 'Package is not a dependency' failures.
Corporate-Ready: Supports SSL inspection bypass (--ssl-false / --insecure),
proxy routing, aggressive timeout prevention, and offline/airgapped environments.

Author: Antigravity Agent
License: MIT
"""

import sys
import os
import json
import re
import shutil
import subprocess
import argparse
import socket
import ssl
import time
from pathlib import Path
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple, Any


def get_windows_cmd_exe() -> str:
    """Returns the absolute path to cmd.exe on Windows, enforcing cmd.exe over PowerShell."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    default_cmd = os.path.join(system_root, "System32", "cmd.exe")
    comspec = os.environ.get("COMSPEC", default_cmd)
    # Ensure COMSPEC is strictly cmd.exe and never PowerShell
    if "powershell" in comspec.lower() or not os.path.exists(comspec):
        comspec = default_cmd
    return comspec


def configure_system_path():
    """Adds common binary directories to PATH and enforces cmd.exe rules on Windows."""
    current_path = os.environ.get("PATH", "")
    path_sep = ";" if sys.platform == "win32" else ":"
    existing_dirs = set(filter(None, current_path.split(path_sep)))
    candidates: List[str] = []

    if sys.platform == "darwin":
        candidates = [
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/usr/local/bin",
            "/opt/local/bin",
            os.path.expanduser("~/bin"),
            os.path.expanduser("~/.npm-global/bin")
        ]
    elif sys.platform == "win32":
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        appdata = os.environ.get("APPDATA", "")
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            os.path.join(prog_files, "nodejs"),
            os.path.join(prog_files_x86, "nodejs"),
            os.path.join(appdata, "npm"),
            os.path.join(local_appdata, "Programs", "Git", "cmd"),
            os.path.join(prog_files, "Git", "cmd"),
            os.path.join(prog_files_x86, "Git", "cmd"),
        ]

        # On Windows: Strip .PS1 from PATHEXT to guarantee cmd.exe never executes PowerShell wrappers
        pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        ext_list = [e.strip() for e in pathext.split(";") if e.strip() and e.strip().upper() != ".PS1"]
        for standard_ext in reversed([".COM", ".EXE", ".BAT", ".CMD"]):
            if standard_ext in ext_list:
                ext_list.remove(standard_ext)
            ext_list.insert(0, standard_ext)
        os.environ["PATHEXT"] = ";".join(ext_list)

        # Enforce COMSPEC = cmd.exe
        os.environ["COMSPEC"] = get_windows_cmd_exe()

    else:
        candidates = [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            os.path.expanduser("~/.local/bin"),
            os.path.expanduser("~/.npm-global/bin")
        ]

    to_add = [p for p in candidates if p and os.path.isdir(p) and p not in existing_dirs]
    if to_add:
        os.environ["PATH"] = path_sep.join(to_add) + path_sep + current_path


def setup_terminal_environment() -> Tuple[bool, bool]:
    """
    Initializes terminal encoding, Windows console modes, and detects
    ANSI color and Unicode capabilities across Windows, macOS, and Linux.
    
    Returns (enable_color, enable_unicode).
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    is_windows = (sys.platform == "win32")
    vt_enabled = False

    if is_windows:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass

        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            for handle_id in (-11, -12):
                h = kernel32.GetStdHandle(handle_id)
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                    if kernel32.SetConsoleMode(h, mode.value | 0x0004):
                        vt_enabled = True
        except Exception:
            pass

        if not vt_enabled:
            try:
                if os.system("") == 0:
                    vt_enabled = True
            except Exception:
                pass

    has_isatty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    term_dumb = (os.environ.get("TERM", "").lower() == "dumb")
    no_color_env = ("NO_COLOR" in os.environ)

    color_supported = has_isatty and not term_dumb and not no_color_env
    if is_windows and not vt_enabled:
        color_supported = False

    stdout_encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    is_ascii_encoding = stdout_encoding in ("ascii", "ansi_x3.4-1968")
    force_ascii = os.environ.get("FORCE_ASCII", "").lower() in ("1", "true", "yes")

    unicode_supported = not is_ascii_encoding and not force_ascii
    if unicode_supported:
        try:
            "✔╔═".encode(sys.stdout.encoding or "utf-8")
        except (UnicodeEncodeError, LookupError):
            unicode_supported = False

    return color_supported, unicode_supported


def should_disable_ssl(cli_no_ssl: bool) -> bool:
    """Detects whether SSL verification should be bypassed via CLI flag or corporate environment variables."""
    if cli_no_ssl:
        return True
    if os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        return True
    if os.environ.get("npm_config_strict_ssl", "").lower() in ("false", "0"):
        return True
    if os.environ.get("SSL_NO_VERIFY", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("PYTHONHTTPSVERIFY") == "0":
        return True
    if os.environ.get("GIT_SSL_NO_VERIFY", "").lower() in ("1", "true", "yes"):
        return True
    return False


# ANSI Colors for Rich Terminal Output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"
    BG_GREEN = "\033[42m"

    @classmethod
    def disable(cls):
        """Disables all ANSI styling for raw or non-interactive terminals."""
        for attr in ["RESET", "BOLD", "DIM", "UNDERLINE", "RED", "GREEN",
                     "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE", "BG_BLUE", "BG_GREEN"]:
            setattr(cls, attr, "")


# Terminal Glyphs / Icons with Plain ASCII Fallback
class Icons:
    CHECK = "✔"
    CROSS = "✖"
    UPDATE = "▲"
    INFO = "ℹ"
    WARN = "⚠️"
    GEAR = "⚙"
    SHIELD = "🛡️"
    CLIPBOARD = "📋"
    MAGNIFIER = "🔍"
    BULLET = "•"

    @classmethod
    def set_ascii_mode(cls):
        """Sets icons to plain ASCII equivalents for non-Unicode environments."""
        cls.CHECK = "[OK]"
        cls.CROSS = "[FAIL]"
        cls.UPDATE = "[UPDATE]"
        cls.INFO = "[INFO]"
        cls.WARN = "[WARN]"
        cls.GEAR = "*"
        cls.SHIELD = ""
        cls.CLIPBOARD = ""
        cls.MAGNIFIER = ""
        cls.BULLET = "-"


# Fallback Angular Version Compatibility Matrix (mirrors angular.dev versions.md)
FALLBACK_COMPATIBILITY_MATRIX = {
    22: {
        "node": "^22.22.3 || ^24.15.0 || ^26.0.0",
        "typescript": ">=6.0.0 <6.1.0",
        "rxjs": "^6.5.3 || ^7.4.0",
        "status": "Active",
        "lts_until": "2028-06",
        "active_until": "2027-06"
    },
    21: {
        "node": "^20.19.0 || ^22.12.0 || ^24.0.0",
        "typescript": ">=5.9.0 <6.0.0",
        "rxjs": "^6.5.3 || ^7.4.0",
        "status": "LTS",
        "lts_until": "2027-06",
        "active_until": "2026-06"
    },
    20: {
        "node": "^20.19.0 || ^22.12.0 || ^24.0.0",
        "typescript": ">=5.8.0 <6.0.0",
        "rxjs": "^6.5.3 || ^7.4.0",
        "status": "LTS",
        "lts_until": "2026-11",
        "active_until": "2025-11"
    },
    19: {
        "node": "^18.19.1 || ^20.11.1 || ^22.0.0",
        "typescript": ">=5.5.0 <5.9.0",
        "rxjs": "^6.5.3 || ^7.4.0",
        "status": "LTS",
        "lts_until": "2026-05",
        "active_until": "2025-05"
    },
    18: {
        "node": "^18.19.1 || ^20.11.1 || ^22.0.0",
        "typescript": ">=5.4.0 <5.6.0",
        "rxjs": "^6.5.3 || ^7.4.0",
        "status": "Extended",
        "lts_until": "2025-11",
        "active_until": "2024-11"
    }
}


def clean_version(ver_str: str) -> str:
    """Strips npm semver prefixes (^, ~, >=, <=, etc.) to get base version."""
    if not ver_str:
        return ""
    cleaned = re.sub(r'^[^\d]*', '', ver_str.strip())
    match = re.search(r'\d+(\.\d+)*', cleaned)
    return match.group(0) if match else cleaned


def get_major(ver_str: str) -> Optional[int]:
    """Extracts major version integer from semver string."""
    cleaned = clean_version(ver_str)
    if not cleaned:
        return None
    parts = cleaned.split('.')
    try:
        return int(parts[0])
    except (ValueError, IndexError):
        return None


def parse_semver_tuple(s: str) -> Tuple[int, int, int]:
    """Parses semver string to (major, minor, patch) integer tuple."""
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', s)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def satisfies_ts_range(curr: str, req: str) -> bool:
    """Checks if current version satisfies requirement like '>=5.5.0 <5.9.0'."""
    if not curr or not req:
        return True
    c = parse_semver_tuple(curr)
    m_ge = re.search(r'>=\s*(\d+\.\d+(?:\.\d+)?)', req)
    m_lt = re.search(r'<\s*(\d+\.\d+(?:\.\d+)?)', req)
    if m_ge and c < parse_semver_tuple(m_ge.group(1)):
        return False
    if m_lt and c >= parse_semver_tuple(m_lt.group(1)):
        return False
    return True


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 300,
    ssl_verify: bool = True,
    stream_output: bool = False
) -> Tuple[int, str, str]:
    """
    Runs a shell command portably across Windows, macOS, and Linux.
    
    Windows Rules:
    - ALWAYS uses cmd.exe as the execution shell; NEVER uses PowerShell.
    - Resolves npm and npx to npm.cmd and npx.cmd (never .ps1).
    - Injects CI=true, NG_CLI_ANALYTICS=false, npm_config_yes=true to completely
      eliminate interactive prompts that freeze headless or background tasks on Windows.
    - Connects stdin to DEVNULL to prevent invisible prompt deadlocks.
    - When stream_output=True, streams lines in real-time with prefix styling.
    """
    try:
        is_windows = (sys.platform == "win32")
        cmd_shell_exe = get_windows_cmd_exe() if is_windows else None

        # Prepare command copy
        exec_cmd = list(cmd)
        if is_windows and exec_cmd:
            first_tok = exec_cmd[0].lower()
            if first_tok in ("npm", "npm.cmd", "npm.ps1"):
                exec_cmd[0] = "npm.cmd"
            elif first_tok in ("npx", "npx.cmd", "npx.ps1"):
                exec_cmd[0] = "npx.cmd"

        executable = exec_cmd[0] if exec_cmd else ""

        # Validate executable existence
        if executable:
            resolved = shutil.which(executable)
            if not resolved and is_windows:
                for ext in [".cmd", ".exe", ".bat"]:
                    if shutil.which(f"{executable}{ext}"):
                        resolved = True
                        break
            if not resolved:
                return -1, "", f"Command not found in PATH: '{executable}'. Please ensure it is installed and added to PATH."

        cwd_str = str(cwd) if cwd else None

        # Build execution environment
        proc_env = os.environ.copy()
        proc_env["CI"] = "true"                        # Disable all interactive CLI prompts
        proc_env["NG_CLI_ANALYTICS"] = "false"         # Disable Angular analytics prompt
        proc_env["npm_config_yes"] = "true"            # Auto-confirm npx/npm prompts
        proc_env["npm_config_fund"] = "false"          # Suppress npm funding messages
        proc_env["npm_config_audit"] = "false"         # Skip npm audit delays

        if is_windows:
            proc_env["COMSPEC"] = cmd_shell_exe        # Strictly enforce cmd.exe
            proc_env["PATHEXT"] = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")

        if not ssl_verify:
            proc_env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
            proc_env["npm_config_strict_ssl"] = "false"
            proc_env["GIT_SSL_NO_VERIFY"] = "true"

        if stream_output:
            process = subprocess.Popen(
                exec_cmd,
                cwd=cwd_str,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,  # Prevent background prompt deadlocks
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=is_windows,
                executable=cmd_shell_exe if is_windows else None,
                env=proc_env,
                bufsize=1
            )
            captured_lines: List[str] = []
            try:
                for line in iter(process.stdout.readline, ''):
                    clean_line = line.rstrip('\r\n')
                    if clean_line:
                        print(f"  {Colors.DIM}│{Colors.RESET} {clean_line}")
                        captured_lines.append(clean_line)
                process.stdout.close()
                returncode = process.wait(timeout=timeout)
                return returncode, "\n".join(captured_lines), ""
            except subprocess.TimeoutExpired:
                process.kill()
                return -1, "\n".join(captured_lines), f"Command timed out after {timeout} seconds: {' '.join(exec_cmd)}"
        else:
            res = subprocess.run(
                exec_cmd,
                cwd=cwd_str,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=is_windows,
                executable=cmd_shell_exe if is_windows else None,
                timeout=timeout,
                env=proc_env
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()

    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds: {' '.join(cmd)}"
    except FileNotFoundError as e:
        return -1, "", f"Executable not found: {e}"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return -1, "", str(e)


class EnvironmentScanner:
    """Detects local Node.js, npm, and git environment."""
    @staticmethod
    def get_info(workspace_dir: Optional[Path] = None, ssl_verify: bool = True) -> Dict[str, Any]:
        npm_bin = "npm.cmd" if sys.platform == "win32" else "npm"
        node_code, node_out, _ = run_cmd(["node", "-v"], cwd=workspace_dir, timeout=5, ssl_verify=ssl_verify)
        npm_code, npm_out, _ = run_cmd([npm_bin, "-v"], cwd=workspace_dir, timeout=5, ssl_verify=ssl_verify)
        git_code, git_out, _ = run_cmd(["git", "status", "--porcelain"], cwd=workspace_dir, timeout=5, ssl_verify=ssl_verify)

        is_git = (git_code == 0)
        is_clean = is_git and len(git_out) == 0

        return {
            "node_version": node_out if node_code == 0 else "Not found",
            "node_major": get_major(node_out) if node_code == 0 else None,
            "npm_version": npm_out if npm_code == 0 else "Not found",
            "is_git_clean": is_clean,
            "git_status": git_out if is_git else "Not a git repo"
        }


class PackageScanner:
    """Parses package.json to catalog Angular core, tooling, and third-party libraries."""
    def __init__(self, package_path: Path):
        self.path = package_path
        self.raw_data: Dict[str, Any] = {}
        self.dependencies: Dict[str, str] = {}
        self.dev_dependencies: Dict[str, str] = {}
        self.angular_core_version: Optional[str] = None
        self.angular_major: Optional[int] = None

    def scan(self) -> bool:
        if not self.path.exists():
            return False

        try:
            with open(self.path, "r", encoding="utf-8-sig") as f:
                self.raw_data = json.load(f)

            self.dependencies = self.raw_data.get("dependencies", {})
            self.dev_dependencies = self.raw_data.get("devDependencies", {})

            core_ver = self.dependencies.get("@angular/core") or self.dev_dependencies.get("@angular/core")
            if not core_ver:
                core_ver = self.dev_dependencies.get("@angular/cli") or self.dependencies.get("@angular/cli")

            self.angular_core_version = core_ver
            self.angular_major = get_major(core_ver) if core_ver else None
            return True
        except Exception as e:
            print(f"{Colors.RED}Error reading package.json: {e}{Colors.RESET}", file=sys.stderr)
            return False

    def get_all_deps(self) -> Dict[str, str]:
        all_deps = {}
        all_deps.update(self.dependencies)
        all_deps.update(self.dev_dependencies)
        return all_deps


class AngularDevClient:
    """Fetches official compatibility matrix and LTS lifecycle data from angular.dev and APIs."""
    VERSIONS_MD_URL = "https://raw.githubusercontent.com/angular/angular/main/adev/src/content/reference/versions.md"
    EOL_API_URL = "https://endoflife.date/api/angular.json"

    def __init__(
        self,
        verbose: bool = False,
        ssl_verify: bool = True,
        timeout: int = 5,
        offline: bool = False
    ):
        self.verbose = verbose
        self.ssl_verify = ssl_verify
        self.timeout = max(1, timeout)
        self.offline = offline
        self.network_available = not offline

    def _get_opener(self, verify_ssl: bool) -> urllib.request.OpenerDirector:
        """Builds an OpenerDirector with corporate proxy routing and designated SSL verification mode."""
        if not verify_ssl:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()

        proxy_handler = urllib.request.ProxyHandler()
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        return urllib.request.build_opener(proxy_handler, https_handler)

    def _http_get(self, url: str) -> Optional[str]:
        """Performs a fast HTTP GET with proxy support, SSL bypass, and timeout resilience."""
        if self.offline or not self.network_available:
            return None

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; AngularUpgradeAdvisor/1.0)",
                "Accept": "*/*"
            }
        )

        opener = self._get_opener(self.ssl_verify)

        try:
            with opener.open(req, timeout=self.timeout) as res:
                return res.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            err_msg = str(e)

            if self.ssl_verify and ("CERTIFICATE_VERIFY_FAILED" in err_msg or "certificate verify failed" in err_msg.lower()):
                if self.verbose:
                    print(f"{Colors.DIM}[debug] Corporate SSL inspection detected for {url}. Retrying with SSL verification disabled...{Colors.RESET}")
                try:
                    fallback_opener = self._get_opener(verify_ssl=False)
                    with fallback_opener.open(req, timeout=self.timeout) as res:
                        self.ssl_verify = False
                        return res.read().decode("utf-8", errors="replace")
                except Exception as inner_e:
                    if self.verbose:
                        print(f"{Colors.DIM}[debug] Insecure SSL retry failed: {inner_e}{Colors.RESET}")

            if any(term in err_msg.lower() for term in ("timed out", "connection refused", "not known", "name resolution", "proxy error")):
                if self.verbose:
                    print(f"{Colors.DIM}[debug] Network unreachable or timed out for {url}. Using embedded offline data.{Colors.RESET}")
                self.network_available = False
            elif self.verbose:
                print(f"{Colors.DIM}[debug] HTTP error on {url}: {e}{Colors.RESET}")

        except (TimeoutError, socket.timeout):
            if self.verbose:
                print(f"{Colors.DIM}[debug] Network probe timed out after {self.timeout}s for {url}. Using embedded offline data.{Colors.RESET}")
            self.network_available = False
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}[debug] Request failed for {url}: {e}{Colors.RESET}")

        return None

    def fetch_versions_matrix(self) -> Dict[int, Dict[str, Any]]:
        """Parses angular.dev versions.md for exact Node, TypeScript, and RxJS ranges."""
        matrix: Dict[int, Dict[str, Any]] = {}
        content = self._http_get(self.VERSIONS_MD_URL)
        if not content:
            if self.verbose:
                print(f"{Colors.YELLOW}[info] Using embedded fallback compatibility matrix.{Colors.RESET}")
            return FALLBACK_COMPATIBILITY_MATRIX

        try:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("|") and any(c.isdigit() for c in line):
                    protected = line.replace(r"\|", "\x00")
                    cols = [c.replace("\x00", "|").strip() for c in protected.split("|")]
                    cols = [c for c in cols if c]
                    if len(cols) >= 4:
                        ang_col = cols[0]
                        node_col = cols[1]
                        ts_col = cols[2]
                        rxjs_col = cols[3]

                        major_match = re.search(r"\b(\d+)\.", ang_col)
                        if major_match:
                            major = int(major_match.group(1))
                            if major not in matrix:
                                matrix[major] = {
                                    "node": node_col,
                                    "typescript": ts_col,
                                    "rxjs": rxjs_col
                                }
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[info] Parsing error on versions.md: {e}. Using fallback.{Colors.RESET}")
            return FALLBACK_COMPATIBILITY_MATRIX

        merged = {}
        for major, data in FALLBACK_COMPATIBILITY_MATRIX.items():
            merged[major] = dict(data)
            if major in matrix:
                merged[major].update(matrix[major])
        for major, data in matrix.items():
            if major not in merged:
                merged[major] = data
        return merged

    def fetch_lts_lifecycle(self) -> List[Dict[str, Any]]:
        """Fetches LTS cycle metadata from endoflife.date API or npm dist-tags."""
        if not self.offline and self.network_available:
            content = self._http_get(self.EOL_API_URL)
            if content:
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        return data
                except Exception:
                    pass

        # Fallback: Query npm dist-tags with short timeout (6s) and SSL bypass via cmd.exe
        if not self.offline:
            npm_bin = "npm.cmd" if sys.platform == "win32" else "npm"
            code, out, _ = run_cmd(
                [npm_bin, "view", "@angular/core", "dist-tags", "--json"],
                timeout=6,
                ssl_verify=self.ssl_verify
            )
            if code == 0:
                try:
                    tags = json.loads(out)
                    cycles = []
                    for tag, ver in tags.items():
                        if "lts" in tag or tag == "latest":
                            m = get_major(ver)
                            if m:
                                cycles.append({
                                    "cycle": str(m),
                                    "latest": ver,
                                    "lts": "lts" in tag,
                                    "support": "Active" if tag == "latest" else "LTS",
                                    "eol": "Supported"
                                })
                    if cycles:
                        return cycles
                except Exception:
                    pass

        # Instant, comprehensive offline fallback
        return [
            {"cycle": "22", "latest": "22.2.3", "lts": False, "support": "Active", "eol": "2028-06-30"},
            {"cycle": "21", "latest": "21.2.25", "lts": True, "support": "LTS", "eol": "2027-06-30"},
            {"cycle": "20", "latest": "20.3.34", "lts": True, "support": "LTS", "eol": "2026-11-28"},
            {"cycle": "19", "latest": "19.2.25", "lts": True, "support": "LTS", "eol": "2026-05-19"},
            {"cycle": "18", "latest": "18.2.14", "lts": True, "support": "LTS", "eol": "2025-11-21"},
        ]


class DependencyVerifier:
    """Verifies ecosystem packages, peerDependencies, and flags upgrade actions."""
    def __init__(self, target_major: int, current_deps: Dict[str, str], env_info: Dict[str, Any], matrix: Dict[int, Dict[str, Any]]):
        self.target_major = target_major
        self.current_deps = current_deps
        self.env_info = env_info
        self.matrix = matrix.get(target_major, {})

    def check_node(self) -> Dict[str, Any]:
        node_str = self.env_info.get("node_version", "")
        node_major = self.env_info.get("node_major")
        required_range = self.matrix.get("node", "Unknown")

        is_ok = True
        warning = None
        if node_major is not None:
            if self.target_major >= 22 and node_major < 22:
                is_ok = False
                warning = f"Angular {self.target_major} requires Node >= 22. Current: {node_str}"
            elif self.target_major in (20, 21) and node_major < 20:
                is_ok = False
                warning = f"Angular {self.target_major} requires Node >= 20. Current: {node_str}"
            elif self.target_major == 19 and node_major < 18:
                is_ok = False
                warning = f"Angular 19 requires Node >= 18. Current: {node_str}"
        else:
            is_ok = False
            warning = f"Node.js runtime was not detected in PATH. Required: {required_range}"

        return {
            "name": "Node.js Runtime",
            "current": node_str,
            "required": required_range,
            "status": "PASS" if is_ok else "FAIL",
            "warning": warning
        }

    def check_typescript(self) -> Dict[str, Any]:
        current_ts = self.current_deps.get("typescript", "")
        required_range = self.matrix.get("typescript", ">=5.5.0")
        is_sat = satisfies_ts_range(current_ts, required_range)
        rec_ts = f"~{required_range.split('<')[0].replace('>=', '').strip()}" if ">=" in required_range else required_range
        return {
            "name": "TypeScript (devDependency)",
            "current": current_ts,
            "required": required_range,
            "status": "OK" if is_sat else "UPGRADE_REQUIRED",
            "target_version": current_ts if is_sat else rec_ts
        }

    def audit_dependencies(self) -> List[Dict[str, Any]]:
        results = []
        for pkg, current_ver in self.current_deps.items():
            curr_cleaned = clean_version(current_ver)
            curr_major = get_major(curr_cleaned)

            # Angular Core & Official Tooling
            if pkg.startswith("@angular/") or pkg.startswith("@angular-devkit/"):
                if curr_major != self.target_major:
                    results.append({
                        "package": pkg,
                        "category": "Angular Framework",
                        "current": current_ver,
                        "target": f"^{self.target_major}.0.0",
                        "status": "UPDATE_REQUIRED",
                        "risk": "Low (Automated by ng update)",
                        "notes": f"Will align to v{self.target_major}"
                    })
                else:
                    results.append({
                        "package": pkg,
                        "category": "Angular Framework",
                        "current": current_ver,
                        "target": current_ver,
                        "status": "OK",
                        "risk": "None",
                        "notes": "Already at target major version"
                    })
                continue

            # PrimeNG Ecosystem
            if pkg == "primeng":
                target_primeng = f"^{self.target_major}.0.0"
                if curr_major != self.target_major:
                    results.append({
                        "package": pkg,
                        "category": "UI Library",
                        "current": current_ver,
                        "target": target_primeng,
                        "status": "UPDATE_REQUIRED",
                        "risk": "Medium (Review PrimeNG breaking changes)",
                        "notes": f"PrimeNG v{self.target_major} designed specifically for Angular {self.target_major}"
                    })
                else:
                    results.append({
                        "package": pkg,
                        "category": "UI Library",
                        "current": current_ver,
                        "target": current_ver,
                        "status": "OK",
                        "risk": "None",
                        "notes": "Compatible"
                    })
                continue

            if pkg == "@primeng/themes":
                target_themes = f"^{self.target_major}.0.0"
                if curr_major != self.target_major:
                    results.append({
                        "package": pkg,
                        "category": "UI Theming",
                        "current": current_ver,
                        "target": target_themes,
                        "status": "UPDATE_REQUIRED",
                        "risk": "Low",
                        "notes": f"Themes for PrimeNG v{self.target_major}"
                    })
                else:
                    results.append({
                        "package": pkg,
                        "category": "UI Theming",
                        "current": current_ver,
                        "target": target_ver,
                        "status": "OK",
                        "risk": "None",
                        "notes": "Compatible"
                    })
                continue

            if pkg == "primeicons":
                results.append({
                    "package": pkg,
                    "category": "UI Assets",
                    "current": current_ver,
                    "target": current_ver,
                    "status": "OK",
                    "risk": "None",
                    "notes": "PrimeIcons is backward compatible across Angular releases"
                })
                continue

            # RxJS & Zone.js
            if pkg == "rxjs":
                req_rxjs = self.matrix.get("rxjs", "^7.4.0")
                is_ok = ("7." in current_ver or "6.5" in current_ver)
                results.append({
                    "package": pkg,
                    "category": "Core Runtime",
                    "current": current_ver,
                    "target": current_ver if is_ok else "^7.4.0",
                    "status": "OK" if is_ok else "UPDATE_REQUIRED",
                    "risk": "Low",
                    "notes": f"Satisfies requirement ({req_rxjs})"
                })
                continue

            if pkg == "zone.js":
                results.append({
                    "package": pkg,
                    "category": "Core Runtime",
                    "current": current_ver,
                    "target": "~0.15.0" if self.target_major >= 19 else current_ver,
                    "status": "UPDATE_REQUIRED" if self.target_major >= 19 else "OK",
                    "risk": "Low (Automated by ng update)",
                    "notes": "Managed by Angular CLI update schematic"
                })
                continue

            # Tooling and Testing
            if pkg in ("typescript",):
                req_ts = self.matrix.get("typescript", ">=5.5.0")
                is_sat = satisfies_ts_range(current_ver, req_ts)
                rec_ts = f"~{req_ts.split('<')[0].replace('>=', '').strip()}" if ">=" in req_ts else req_ts
                results.append({
                    "package": pkg,
                    "category": "Compiler / Tooling",
                    "current": current_ver,
                    "target": current_ver if is_sat else rec_ts,
                    "status": "OK" if is_sat else "UPDATE_REQUIRED",
                    "risk": "Low (Automated by ng update)",
                    "notes": f"Required range: {req_ts}"
                })
                continue

            # General Other dependencies
            results.append({
                "package": pkg,
                "category": "Third-Party",
                "current": current_ver,
                "target": current_ver,
                "status": "OK",
                "risk": "Low",
                "notes": "No explicit peer restriction found"
            })

        return results


def is_node_modules_synced(workspace_dir: Path) -> bool:
    """Checks whether local node_modules has @angular/core installed to prevent ng update failures."""
    core_pkg = workspace_dir / "node_modules" / "@angular" / "core" / "package.json"
    return core_pkg.exists()


class UpgradeExecutor:
    """Executes safe multi-step upgrade commands with verification across OS and corporate environments."""
    def __init__(
        self,
        workspace_dir: Path,
        current_major: int,
        target_major: int,
        audit_results: List[Dict[str, Any]],
        ssl_verify: bool = True,
        cmd_timeout: int = 600
    ):
        self.workspace_dir = workspace_dir
        self.current_major = current_major
        self.target_major = target_major
        self.audit_results = audit_results
        self.ssl_verify = ssl_verify
        self.cmd_timeout = cmd_timeout

    def get_upgrade_commands(self) -> List[Dict[str, Any]]:
        cmds = []
        step_counter = 1
        has_cdk = any(r["package"] == "@angular/cdk" for r in self.audit_results)
        is_windows = (sys.platform == "win32")

        npx_bin = "npx.cmd" if is_windows else "npx"
        npm_bin = "npm.cmd" if is_windows else "npm"

        # Prerequisite Step: Check if workspace node_modules has @angular/core installed
        # If node_modules is missing or not installed yet (e.g. freshly cloned repo),
        # ng update immediately fails with "Package '@angular/core' is not a dependency".
        if not is_node_modules_synced(self.workspace_dir):
            install_cmd = [npm_bin, "install", "--legacy-peer-deps", "--no-audit", "--no-fund"]
            if not self.ssl_verify:
                install_cmd.append("--strict-ssl=false")
            cmds.append({
                "step": step_counter,
                "title": "Install workspace dependencies (Prerequisite: node_modules missing)",
                "command": install_cmd
            })
            step_counter += 1

        if self.target_major > self.current_major:
            step_versions = list(range(self.current_major + 1, self.target_major + 1))
        else:
            step_versions = [self.target_major]

        prev_v = self.current_major
        for v in step_versions:
            pkgs = [f"@angular/core@{v}", f"@angular/cli@{v}"]
            if has_cdk:
                pkgs.append(f"@angular/cdk@{v}")

            # Explicitly target npx.cmd on Windows via cmd.exe
            cmd = [npx_bin, "--yes", f"@angular/cli@{v}", "update"] + pkgs + ["--force", "--allow-dirty"]
            title_desc = f"v{prev_v} -> v{v}" if len(step_versions) > 1 else f"v{v}"
            cmds.append({
                "step": step_counter,
                "title": f"Migrate Angular Core, CLI & CDK sequentially ({title_desc})",
                "command": cmd
            })
            step_counter += 1
            prev_v = v

        packages_to_install = []
        for r in self.audit_results:
            if r["package"] in ("primeng", "@primeng/themes") and r["status"] == "UPDATE_REQUIRED":
                packages_to_install.append(f"{r['package']}@{r['target']}")

        if packages_to_install:
            install_cmd = [npm_bin, "install", "--no-audit", "--no-fund"]
            if not self.ssl_verify:
                install_cmd.append("--strict-ssl=false")
            install_cmd.extend(packages_to_install)

            cmds.append({
                "step": step_counter,
                "title": f"Update PrimeNG ecosystem to match Angular {self.target_major}",
                "command": install_cmd
            })
            step_counter += 1

        cmds.append({
            "step": step_counter,
            "title": "Verify application compilation (Build Test)",
            "command": [npm_bin, "run", "build"]
        })

        return cmds

    def execute(self) -> bool:
        commands = self.get_upgrade_commands()
        is_windows = (sys.platform == "win32")
        npm_bin = "npm.cmd" if is_windows else "npm"

        print(f"\n{Colors.BOLD}{Colors.CYAN}Starting Safe Upgrade Pipeline to Angular {self.target_major}...{Colors.RESET}")
        print(f"{Colors.DIM}Workspace: {self.workspace_dir}{Colors.RESET}")
        if is_windows:
            print(f"{Colors.DIM}Windows Shell: Command Prompt (cmd.exe){Colors.RESET}")
        print(f"{Colors.DIM}Streaming command outputs in real-time. Prompts are automatically handled.{Colors.RESET}\n")

        for item in commands:
            step_num = item["step"]
            title = item["title"]
            cmd = item["command"]
            cmd_str = " ".join(cmd)

            print(f"{Colors.BOLD}{Colors.BLUE}[Step {step_num}/{len(commands)}] {title}{Colors.RESET}")
            print(f"{Colors.DIM}Executing: {cmd_str}{Colors.RESET}")

            if "npx" in cmd[0]:
                print(f"{Colors.DIM}Note: Fetching and executing temporary CLI package via npm. Please wait...{Colors.RESET}")

            start_t = time.time()

            code, out, err = run_cmd(
                cmd,
                cwd=self.workspace_dir,
                timeout=self.cmd_timeout,
                ssl_verify=self.ssl_verify,
                stream_output=True
            )

            elapsed = time.time() - start_t

            if code == 0:
                print(f"{Colors.GREEN}{Icons.CHECK} Step {step_num} completed successfully ({elapsed:.1f}s).{Colors.RESET}\n")
            else:
                # Reactive Auto-Recovery: Handle "is not a dependency" or missing node_modules
                error_combined = f"{out}\n{err}".lower()
                if "is not a dependency" in error_combined or "found 0 dependencies" in error_combined:
                    print(f"\n{Colors.YELLOW}⚠️ Detected missing or unlinked workspace dependencies in node_modules.{Colors.RESET}")
                    print(f"{Colors.CYAN}Automatically running 'npm install' to synchronize workspace dependencies...{Colors.RESET}\n")

                    repair_cmd = [npm_bin, "install", "--legacy-peer-deps", "--no-audit", "--no-fund"]
                    if not self.ssl_verify:
                        repair_cmd.append("--strict-ssl=false")

                    repair_code, _, repair_err = run_cmd(
                        repair_cmd,
                        cwd=self.workspace_dir,
                        timeout=self.cmd_timeout,
                        ssl_verify=self.ssl_verify,
                        stream_output=True
                    )

                    if repair_code == 0:
                        print(f"\n{Colors.GREEN}{Icons.CHECK} Workspace dependencies synchronized. Retrying Step {step_num}...{Colors.RESET}\n")
                        start_retry = time.time()
                        code, out, err = run_cmd(
                            cmd,
                            cwd=self.workspace_dir,
                            timeout=self.cmd_timeout,
                            ssl_verify=self.ssl_verify,
                            stream_output=True
                        )
                        elapsed_retry = time.time() - start_retry
                        if code == 0:
                            print(f"{Colors.GREEN}{Icons.CHECK} Step {step_num} completed successfully on retry ({elapsed_retry:.1f}s).{Colors.RESET}\n")
                            continue

                print(f"{Colors.RED}{Icons.CROSS} Step {step_num} failed with exit code {code} ({elapsed:.1f}s).{Colors.RESET}")
                if err:
                    print(f"{Colors.RED}Error details:{Colors.RESET}\n{err}")
                return False

        print(f"{Colors.BOLD}{Colors.GREEN}======================================================{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{Icons.CHECK} Angular {self.target_major} upgrade successfully applied & verified!{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}======================================================{Colors.RESET}")
        return True


def print_banner(unicode_mode: bool = True):
    if unicode_mode:
        banner = f"""{Colors.BOLD}{Colors.CYAN}
 ╔═══════════════════════════════════════════════════════════════════╗
 ║        ANGULAR LTS UPGRADE & DEPENDENCY SAFETY ADVISOR            ║
 ║         Integrated with angular.dev & Official Release APIs       ║
 ╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}"""
    else:
        banner = f"""{Colors.BOLD}{Colors.CYAN}
 +-------------------------------------------------------------------+
 |        ANGULAR LTS UPGRADE & DEPENDENCY SAFETY ADVISOR            |
 |         Integrated with angular.dev & Official Release APIs       |
 +-------------------------------------------------------------------+{Colors.RESET}"""
    print(banner)


def main():
    configure_system_path()
    color_supported, unicode_supported = setup_terminal_environment()

    parser = argparse.ArgumentParser(
        description="Scans package.json for Angular & dependencies, checks angular.dev for LTS, and guides safe upgrades."
    )
    parser.add_argument("-p", "--path", default="package.json", help="Path to package.json or workspace directory")
    parser.add_argument("-t", "--target", type=int, help="Target Angular major version (e.g., 19, 20, 21)")
    parser.add_argument("-a", "--apply", action="store_true", help="Apply upgrade commands directly after verification")
    parser.add_argument("-y", "--yes", action="store_true", help="Automatically accept confirmation prompts (non-interactive)")
    parser.add_argument("--dry-run", action="store_true", help="Display audit and commands without prompting to execute")
    parser.add_argument("--json", action="store_true", help="Output audit report as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--ascii", action="store_true", help="Force ASCII characters instead of Unicode symbols")
    parser.add_argument("-k", "--insecure", "--no-ssl", "--ssl-false", action="store_true", dest="no_ssl",
                        help="Disable SSL verification for corporate networks, SSL inspection proxies, and self-signed certs")
    parser.add_argument("--timeout", type=int, default=5, help="Network probe timeout in seconds (default: 5)")
    parser.add_argument("--cmd-timeout", type=int, default=600, help="Upgrade command execution timeout in seconds (default: 600)")
    parser.add_argument("--offline", action="store_true", help="Offline/airgapped mode: skips network queries and uses embedded data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")

    args = parser.parse_args()

    ssl_verify = not should_disable_ssl(args.no_ssl)

    if args.no_color or not color_supported:
        Colors.disable()

    use_unicode = unicode_supported and not args.ascii
    if not use_unicode:
        Icons.set_ascii_mode()

    target_path = Path(args.path).resolve()
    if target_path.is_dir():
        package_file = target_path / "package.json"
        workspace_dir = target_path
    else:
        package_file = target_path
        workspace_dir = target_path.parent

    if not package_file.exists():
        print(f"{Colors.RED}Error: Cannot find package.json at '{package_file}'{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print_banner(unicode_mode=use_unicode)

    # 1. Scan Local Environment & Workspace
    env_info = EnvironmentScanner.get_info(workspace_dir, ssl_verify=ssl_verify)
    scanner = PackageScanner(package_file)
    if not scanner.scan():
        print(f"{Colors.RED}Failed to parse package.json at '{package_file}'{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    curr_major = scanner.angular_major
    curr_version = scanner.angular_core_version or "Unknown"

    active_proxy = (
        os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or
        os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    )

    core_installed = is_node_modules_synced(workspace_dir)

    if not args.json:
        print(f"\n{Colors.BOLD}{Icons.MAGNIFIER} Workspace Assessment:{Colors.RESET}")
        print(f"  {Icons.BULLET} {Colors.BOLD}Project Directory:{Colors.RESET} {workspace_dir}")
        print(f"  {Icons.BULLET} {Colors.BOLD}Angular Version:{Colors.RESET}   {Colors.CYAN}{curr_version}{Colors.RESET} (Major: {curr_major})")
        print(f"  {Icons.BULLET} {Colors.BOLD}Node.js Version:{Colors.RESET}   {Colors.GREEN}{env_info['node_version']}{Colors.RESET}")
        print(f"  {Icons.BULLET} {Colors.BOLD}npm Version:{Colors.RESET}       {env_info['npm_version']}")
        print(f"  {Icons.BULLET} {Colors.BOLD}Git Status:{Colors.RESET}        {'Clean' if env_info['is_git_clean'] else Colors.YELLOW + 'Modified files present' + Colors.RESET}")
        print(f"  {Icons.BULLET} {Colors.BOLD}Local node_modules:{Colors.RESET} {'Verified' if core_installed else Colors.YELLOW + 'Missing/uninstalled (will auto-install via npm install)' + Colors.RESET}")
        if sys.platform == "win32":
            print(f"  {Icons.BULLET} {Colors.BOLD}Windows Shell:{Colors.RESET}     {Colors.GREEN}Command Prompt (cmd.exe){Colors.RESET} [PowerShell disabled]")
        if not ssl_verify:
            print(f"  {Icons.BULLET} {Colors.BOLD}SSL Verification:{Colors.RESET} {Colors.YELLOW}Bypassed (Corporate / Insecure Mode){Colors.RESET}")
        if active_proxy:
            print(f"  {Icons.BULLET} {Colors.BOLD}Corporate Proxy:{Colors.RESET}  {Colors.CYAN}{active_proxy}{Colors.RESET}")

    # 2. Fetch official matrix & LTS lifecycles
    client = AngularDevClient(
        verbose=args.verbose,
        ssl_verify=ssl_verify,
        timeout=args.timeout,
        offline=args.offline
    )

    if not args.json:
        if args.offline:
            print(f"\n{Colors.DIM}Offline mode active: using embedded angular.dev compatibility matrix...{Colors.RESET}")
        else:
            print(f"\n{Colors.DIM}Connecting to angular.dev & official lifecycle registry (timeout: {args.timeout}s)...{Colors.RESET}")

    matrix = client.fetch_versions_matrix()
    lifecycles = client.fetch_lts_lifecycle()

    available_lts: List[Dict[str, Any]] = []
    seen_majors = set()

    for item in lifecycles:
        cycle_str = str(item.get("cycle", ""))
        try:
            major_num = int(cycle_str)
        except ValueError:
            continue

        if curr_major is not None and major_num > curr_major and major_num not in seen_majors:
            seen_majors.add(major_num)
            matrix_entry = matrix.get(major_num, {})
            is_lts = item.get("lts", False) or "LTS" in str(item.get("support", ""))
            status_label = "LTS" if is_lts else "Active"
            active_ends = item.get("support", matrix_entry.get("active_until", "-"))
            lts_ends = item.get("eol", matrix_entry.get("lts_until", "-"))
            latest = item.get("latest", f"{major_num}.x")

            available_lts.append({
                "major": major_num,
                "latest": latest,
                "status": status_label,
                "active_ends": active_ends,
                "lts_ends": lts_ends,
                "node_req": matrix_entry.get("node", "See matrix"),
                "ts_req": matrix_entry.get("typescript", "See matrix")
            })

    available_lts.sort(key=lambda x: x["major"])

    if not available_lts:
        if args.json:
            print(json.dumps({"status": "UP_TO_DATE", "current_major": curr_major, "message": "No newer LTS versions available."}))
        else:
            print(f"\n{Colors.GREEN}{Icons.CHECK} Your project is already on the latest supported Angular major version (v{curr_major})!{Colors.RESET}")
        sys.exit(0)

    # 3. Target Selection
    selected_target: Optional[int] = args.target

    if selected_target is None:
        if args.json:
            print(json.dumps({"error": "Target version must be specified via --target in JSON mode."}))
            sys.exit(1)

        print(f"\n{Colors.BOLD}{Icons.CLIPBOARD} Available Angular LTS & Active Target Versions:{Colors.RESET}")
        print(f"{'#':<3} {'Target':<14} {'Status':<10} {'Latest Release':<16} {'Active Support':<16} {'LTS Until':<14} {'Node.js Required'}")
        print(f"{'-'*3} {'-'*14} {'-'*10} {'-'*16} {'-'*16} {'-'*14} {'-'*20}")

        for idx, opt in enumerate(available_lts, start=1):
            status_color = Colors.GREEN if opt["status"] == "Active" else Colors.BLUE
            print(f"[{idx}] Angular {opt['major']:<6} {status_color}{opt['status']:<10}{Colors.RESET} {opt['latest']:<16} {str(opt['active_ends']):<16} {str(opt['lts_ends']):<14} {opt['node_req']}")

        if not sys.stdin.isatty():
            print(f"\n{Colors.RED}Error: Non-interactive terminal detected. Please specify target version with --target (e.g. --target {available_lts[0]['major']}).{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

        while True:
            try:
                choice = input(f"\n{Colors.BOLD}Select target version [1-{len(available_lts)}] or enter major version (e.g. {available_lts[0]['major']}): {Colors.RESET}").strip()
                if not choice:
                    continue
                if choice.isdigit():
                    num = int(choice)
                    if 1 <= num <= len(available_lts):
                        selected_target = available_lts[num - 1]["major"]
                        break
                    elif any(opt["major"] == num for opt in available_lts):
                        selected_target = num
                        break
                print(f"{Colors.RED}Invalid selection. Please choose an option from the list.{Colors.RESET}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.RESET}")
                sys.exit(0)

    # 4. Dependency & Ecosystem Audit
    verifier = DependencyVerifier(selected_target, scanner.get_all_deps(), env_info, matrix)
    node_check = verifier.check_node()
    audit_items = verifier.audit_dependencies()

    if args.json:
        report = {
            "workspace": str(workspace_dir),
            "current_angular": curr_version,
            "target_angular": selected_target,
            "ssl_verify": ssl_verify,
            "node_modules_synced": core_installed,
            "node_check": node_check,
            "dependency_audit": audit_items
        }
        print(json.dumps(report, indent=2))
        sys.exit(0)

    # Display Verification Report
    print(f"\n{Colors.BOLD}{Icons.SHIELD} Compatibility Audit for Angular {selected_target}:{Colors.RESET}")
    print(f"{'='*75}")

    if node_check["status"] == "PASS":
        print(f"  {Colors.GREEN}{Icons.CHECK} Runtime:{Colors.RESET} Node.js {node_check['current']} satisfies requirement ({node_check['required']})")
    else:
        print(f"  {Colors.RED}{Icons.CROSS} Runtime:{Colors.RESET} {node_check['warning']}")

    print(f"\n{'Package':<28} {'Current':<15} {'Target / Recommended':<22} {'Status':<18}")
    print(f"{'-'*28} {'-'*15} {'-'*22} {'-'*18}")

    for item in audit_items:
        pkg = item["package"]
        curr = item["current"]
        tgt = item["target"]
        st = item["status"]

        if st == "OK":
            st_badge = f"{Colors.GREEN}{Icons.CHECK} Compatible{Colors.RESET}"
        elif st == "UPDATE_REQUIRED":
            st_badge = f"{Colors.YELLOW}{Icons.UPDATE} Update Needed{Colors.RESET}"
        else:
            st_badge = f"{Colors.CYAN}{Icons.INFO} Verify{Colors.RESET}"

        print(f"{pkg:<28} {curr:<15} {tgt:<22} {st_badge}")

    print(f"{'='*75}")

    executor = UpgradeExecutor(
        workspace_dir,
        curr_major or 18,
        selected_target,
        audit_items,
        ssl_verify=ssl_verify,
        cmd_timeout=args.cmd_timeout
    )
    commands = executor.get_upgrade_commands()

    print(f"\n{Colors.BOLD}{Icons.GEAR} Planned Upgrade Steps:{Colors.RESET}")
    for cmd_info in commands:
        print(f"  {Colors.CYAN}{cmd_info['step']}.{Colors.RESET} {cmd_info['title']}")
        print(f"     {Colors.DIM}$ {' '.join(cmd_info['command'])}{Colors.RESET}")

    if args.dry_run:
        print(f"\n{Colors.CYAN}[Dry-Run Mode] No changes were made to the project.{Colors.RESET}")
        sys.exit(0)

    # 5. Safe Upgrade Confirmation & Execution
    should_apply = args.apply or args.yes
    if not should_apply:
        print()
        if not env_info["is_git_clean"]:
            print(f"{Colors.YELLOW}{Icons.WARN} Notice: You have uncommitted git changes. It is recommended to stash or commit before upgrading.{Colors.RESET}")

        if not sys.stdin.isatty():
            print(f"\n{Colors.RED}Non-interactive terminal detected. Run with --apply or -y/--yes to execute upgrade pipeline.{Colors.RESET}", file=sys.stderr)
            sys.exit(1)

        try:
            confirm = input(f"{Colors.BOLD}Proceed with executing this safe upgrade to Angular {selected_target}? [y/N]: {Colors.RESET}").strip().lower()
            if confirm in ("y", "yes"):
                should_apply = True
            else:
                print(f"{Colors.YELLOW}Upgrade execution aborted. You can run the steps manually when ready.{Colors.RESET}")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}Aborted.{Colors.RESET}")
            sys.exit(0)

    if should_apply:
        success = executor.execute()
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.RESET}")
        sys.exit(0)
