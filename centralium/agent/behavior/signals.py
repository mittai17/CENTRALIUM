"""Small shared, dependency-free classifiers used by behavior/lolbins/persistence/ransomware."""

from __future__ import annotations

import re

from centralium.agent.normalization.common import basename_any, ext_of

_SUSPICIOUS_DIR = [
    (re.compile(r"^/dev/shm(/|$)"), 1.0),
    (re.compile(r"^/(var/)?tmp(/|$)"), 0.8),
    (re.compile(r"\\\$recycle\.bin\\", re.I), 0.9),
    (re.compile(r"\\appdata\\local\\temp\\", re.I), 0.8),
    (re.compile(r"\\windows\\temp\\", re.I), 0.8),
    (re.compile(r"\\users\\public\\", re.I), 0.8),
    (re.compile(r"\\programdata\\(?!microsoft\\)", re.I), 0.5),
    (re.compile(r"\\appdata\\(roaming|local)\\", re.I), 0.4),
    (re.compile(r"\\downloads\\", re.I), 0.5),
    (re.compile(r"/downloads/"), 0.4),
    (re.compile(r"/\.[^/.][^/]*/"), 0.3),  # hidden directory
]
_SYSTEM_DIR = re.compile(
    r"^(/usr/(local/)?(s?bin|lib)|/s?bin|/opt|c:\\windows\\(system32|syswow64|sysnative)|c:\\program files)",
    re.I,
)

EXEC_EXTS = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".scr",
        ".com",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
        ".msi",
        ".lnk",
        ".jar",
        ".sh",
        ".py",
        ".pl",
        ".so",
        ".elf",
        ".cpl",
        ".sct",
    }
)
RANSOM_EXTS = frozenset(
    {
        ".locked",
        ".encrypted",
        ".enc",
        ".crypt",
        ".crypted",
        ".crypto",
        ".lockbit",
        ".ryk",
        ".ryuk",
        ".wncry",
        ".wnry",
        ".wcry",
        ".conti",
        ".blackcat",
        ".akira",
        ".royal",
        ".basta",
        ".hive",
        ".cerber",
        ".locky",
        ".zepto",
        ".petya",
        ".djvu",
        ".stop",
        ".medusa",
        ".babyk",
        ".phobos",
        ".dharma",
        ".gandcrab",
        ".crab",
        ".readme",
        ".id",
        ".pay",
        ".ransom",
        ".lock",
        ".cry",
        ".aes",
    }
)
RANSOM_NOTE = re.compile(
    r"(readme|how[_ -]?to[_ -]?(decrypt|recover|restore)|restore[_ -]?(my[_ -]?)?files|"
    r"decrypt[_ -]?(instructions|files)|"
    r"recover[_ -]?files|_?readme_?|!!!.*read|your[_ -]?files)",
    re.I,
)
SCRIPT_INTERPRETERS = frozenset(
    {
        "powershell",
        "pwsh",
        "cmd",
        "wscript",
        "cscript",
        "mshta",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "bash",
        "sh",
        "dash",
        "zsh",
        "node",
        "php",
        "lua",
        "osascript",
    }
)
OFFICE = frozenset(
    {
        "winword",
        "excel",
        "powerpnt",
        "outlook",
        "onenote",
        "msaccess",
        "mspub",
        "visio",
        "acrord32",
        "soffice",
    }
)
BROWSERS = frozenset(
    {"chrome", "msedge", "firefox", "iexplore", "brave", "opera", "chromium", "vivaldi", "safari"}
)
SERVICE_PARENTS = frozenset(
    {
        "httpd",
        "apache2",
        "nginx",
        "php-fpm",
        "php-fpm8",
        "php",
        "tomcat",
        "java",
        "w3wp",
        "sqlservr",
        "mysqld",
        "postgres",
        "redis-server",
        "node",
        "gunicorn",
        "uwsgi",
        "wmiprvse",
        "wmic",
        "mssql",
    }
)
SERVICE_ACCOUNTS = re.compile(
    r"^(www-data|apache|nginx|nobody|tomcat|httpd|www|postgres|mysql|redis|daemon|"
    r"nt authority\\(network service|local service)|iis apppool\\.*)$",
    re.I,
)


def norm_name(name: str | None) -> str:
    """Lower-case process name without .exe and version suffix (python3.12 -> python3)."""
    if not name:
        return ""
    n = basename_any(name) or ""
    n = n.lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return n


def path_risk(path: str | None) -> float:
    """0..1 risk of a file/exec location (temp, shm, public, recycle bin, hidden, downloads...)."""
    if not path:
        return 0.0
    return max((w for rx, w in _SUSPICIOUS_DIR if rx.search(path)), default=0.0)


def in_system_dir(path: str | None) -> bool:
    return bool(path and _SYSTEM_DIR.match(path))


def is_exec_path(path: str | None) -> bool:
    return ext_of(path) in EXEC_EXTS


def is_ransom_ext(ext: str) -> bool:
    return ext.lower() in RANSOM_EXTS


def is_ransom_note(path: str | None) -> bool:
    base = basename_any(path)
    return bool(
        base and RANSOM_NOTE.search(base) and ext_of(base) in {".txt", ".html", ".hta", ".url", ".png", ""}
    )


# --------------------------------------------------------------------------- shadow copy / ancestry
_SHADOW_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "vssadmin_delete",
        re.compile(r"\bvssadmin(\.exe)?\b.*\b(delete\s+shadows|resize\s+shadowstorage)", re.I | re.S),
    ),
    ("wmic_shadowcopy", re.compile(r"\bwmic(\.exe)?\b.*\bshadowcopy\b.*\bdelete\b", re.I | re.S)),
    (
        "ps_shadowcopy",
        re.compile(
            r"(get-wmiobject|get-ciminstance|gwmi)\s+.*win32_shadowcopy.*(delete|remove)", re.I | re.S
        ),
    ),
    (
        "bcdedit_recovery",
        re.compile(
            r"\bbcdedit(\.exe)?\b.*(recoveryenabled\s+(no|off)|bootstatuspolicy\s+ignoreallfailures)",
            re.I | re.S,
        ),
    ),
    (
        "wbadmin_delete",
        re.compile(r"\bwbadmin(\.exe)?\b.*\bdelete\s+(catalog|systemstatebackup|backup)", re.I | re.S),
    ),
    ("diskshadow_delete", re.compile(r"\bdiskshadow(\.exe)?\b.*\bdelete\s+shadows", re.I | re.S)),
    ("wevtutil_clear", re.compile(r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b", re.I)),
    ("cipher_wipe", re.compile(r"\bcipher(\.exe)?\s+/w[:\s]", re.I)),
    (
        "lnx_snapshot_delete",
        re.compile(
            r"\b(btrfs\s+subvolume\s+delete|zfs\s+destroy\s+\S*@|lvremove\b.*snap|timeshift\s+--delete)",
            re.I | re.S,
        ),
    ),
]


def shadow_command_kind(cmdline: str | None) -> str | None:
    """Return the id of the backup/shadow-copy destruction command pattern matched, if any."""
    if not cmdline:
        return None
    low = cmdline.lower()
    if not any(
        t in low
        for t in (
            "vss",
            "shadow",
            "bcdedit",
            "wbadmin",
            "wevtutil",
            "cipher",
            "btrfs",
            "zfs",
            "lvremove",
            "timeshift",
        )
    ):
        return None
    for kind, rx in _SHADOW_PATTERNS:
        if rx.search(cmdline):
            return kind
    return None


def ancestry_risk(parent: str | None, child: str | None, child_exe: str | None = None) -> float:
    """Static 0..1 risk of a parent->child chain (Office/browser/service spawning interpreters, etc.)."""
    p, c = norm_name(parent), norm_name(child)
    if not p or not c:
        return 0.0
    interp = c in SCRIPT_INTERPRETERS or c in {
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "wmic",
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
    }
    risk = 0.0
    if p in OFFICE and interp:
        risk = 0.95
    elif (p in {"wmiprvse", "winrm", "wsmprovhost", "psexesvc"} and interp) or (
        p in SERVICE_PARENTS and c in SCRIPT_INTERPRETERS
    ):
        risk = 0.8
    elif p in BROWSERS and interp:
        risk = 0.6
    elif p in {"wscript", "cscript", "mshta"} and c in {"powershell", "pwsh", "cmd"}:
        risk = 0.8
    elif p in {"cmd", "powershell", "pwsh"} and c in {"powershell", "pwsh"} and p != c:
        risk = 0.2
    return max(risk, 0.7 * path_risk(child_exe))
