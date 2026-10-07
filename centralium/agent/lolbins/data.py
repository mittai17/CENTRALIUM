"""LOLBin knowledge base (Windows + Linux lists from the spec) and command-line signal rules.

A LOLBin is a legitimate, signed/OS-shipped binary. Presence alone is NEVER malicious: these
rules only contribute *context signals* that the detector combines with parent, user, path,
destination and frequency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from centralium.agent.models import AttackStage


@dataclass(frozen=True)
class LolbinSpec:
    name: str
    platform: str  # windows|linux
    techniques: tuple[str, ...]
    stage: AttackStage
    description: str


@dataclass(frozen=True)
class CmdSignal:
    sid: str
    pattern: re.Pattern[str]
    weight: float  # 0-100 evidence strength (combined noisy-OR)
    description: str
    techniques: tuple[str, ...] = ()


def _s(sid: str, rx: str, w: float, desc: str, *tech: str) -> CmdSignal:
    return CmdSignal(sid, re.compile(rx, re.IGNORECASE | re.DOTALL), w, desc, tuple(tech))


_EX = AttackStage.EXECUTION
_DE = AttackStage.DEFENSE_EVASION
_C2 = AttackStage.COMMAND_AND_CONTROL

LOLBINS: dict[str, LolbinSpec] = {
    s.name: s
    for s in [
        LolbinSpec("powershell", "windows", ("T1059.001",), _EX, "PowerShell scripting engine"),
        LolbinSpec("cmd", "windows", ("T1059.003",), _EX, "Windows command shell"),
        LolbinSpec("wscript", "windows", ("T1059.005",), _EX, "Windows Script Host (GUI)"),
        LolbinSpec("cscript", "windows", ("T1059.005",), _EX, "Windows Script Host (console)"),
        LolbinSpec("mshta", "windows", ("T1218.005",), _DE, "HTML Application host"),
        LolbinSpec("rundll32", "windows", ("T1218.011",), _DE, "DLL proxy execution"),
        LolbinSpec(
            "regsvr32", "windows", ("T1218.010",), _DE, "COM registration / scriptlet proxy execution"
        ),
        LolbinSpec("certutil", "windows", ("T1105", "T1140"), _C2, "Certificate utility (download/decode)"),
        LolbinSpec("bitsadmin", "windows", ("T1197", "T1105"), _C2, "BITS jobs (download/persist)"),
        LolbinSpec("wmic", "windows", ("T1047",), _EX, "WMI command line"),
        LolbinSpec("bash", "linux", ("T1059.004",), _EX, "Bourne-again shell"),
        LolbinSpec("sh", "linux", ("T1059.004",), _EX, "POSIX shell"),
        LolbinSpec("curl", "linux", ("T1105",), _C2, "HTTP transfer tool"),
        LolbinSpec("wget", "linux", ("T1105",), _C2, "HTTP download tool"),
        LolbinSpec("python", "linux", ("T1059.006",), _EX, "Python interpreter"),
        LolbinSpec("perl", "linux", ("T1059",), _EX, "Perl interpreter"),
        LolbinSpec("nc", "linux", ("T1095", "T1059.004"), _C2, "netcat"),
        LolbinSpec("socat", "linux", ("T1095", "T1572"), _C2, "socat relay"),
    ]
}

ALIASES = {
    "pwsh": "powershell",
    "powershell_ise": "powershell",
    "dash": "sh",
    "ash": "sh",
    "zsh": "bash",
    "ncat": "nc",
    "netcat": "nc",
    "nc.traditional": "nc",
    "nc.openbsd": "nc",
    "python2": "python",
    "python3": "python",
    "perl5": "perl",
}


def canonical_lolbin(norm_name: str) -> str | None:
    """Map a normalized process name to a LOLBIN key (None if not a tracked LOLBin)."""
    n = ALIASES.get(norm_name, norm_name)
    if n in LOLBINS:
        return n
    m = re.match(r"^(python|perl)[\d.]+$", norm_name)
    return m.group(1) if m else None


_INTERP_SOCK = r"(socket|pty\.spawn|subprocess|os\.system|os\.dup2|exec\()"

CMD_SIGNALS: dict[str, list[CmdSignal]] = {
    "powershell": [
        _s(
            "ps_encoded",
            r"\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
            45,
            "encoded command",
            "T1027",
            "T1059.001",
        ),
        _s("ps_hidden", r"-w(indowstyle)?\s+hidden|-win\s+hidden", 20, "hidden window", "T1564.003"),
        _s("ps_iex", r"\b(iex|invoke-expression)\b", 25, "Invoke-Expression", "T1059.001"),
        _s(
            "ps_download",
            r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|start-bitstransfer|\bcurl\b.*http",
            30,
            "network download cradle",
            "T1105",
        ),
        _s("ps_bypass", r"-(ep|executionpolicy)\s+bypass", 15, "execution policy bypass", "T1059.001"),
        _s("ps_b64", r"frombase64string", 25, "base64 decode", "T1140"),
        _s(
            "ps_reflect",
            r"\[reflection\.assembly\]::load|add-type\s+-?memberdefinition|virtualalloc",
            25,
            "reflective load",
            "T1620",
        ),
        _s("ps_amsi", r"amsiutils|amsiinitfailed|amsicontext", 70, "AMSI tampering", "T1562.001"),
        _s("ps_cred", r"invoke-mimikatz|sekurlsa|lsass.*minidump", 90, "credential dumping", "T1003.001"),
        _s("ps_noprofile", r"-nop(rofile)?\b", 8, "no profile"),
    ],
    "cmd": [
        _s(
            "cmd_chain",
            r"/c\s+.*\b(powershell|certutil|bitsadmin|mshta|wscript|cscript|curl|bash)\b",
            15,
            "cmd launching another LOLBin",
            "T1059.003",
        ),
        _s("cmd_caret", r"(\^.*){4,}", 20, "caret obfuscation", "T1027"),
        _s(
            "cmd_recon",
            r"\b(whoami\s+/(priv|all)|net\s+(user|group|localgroup)\b.*(/add|/domain)|nltest\s+/)",
            20,
            "recon/account tooling",
            "T1087",
        ),
    ],
    "wscript": [
        _s(
            "ws_userdir",
            r"(\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\)[^\s\"]*\.(js|jse|vbs|vbe|wsf)",
            35,
            "script from user-writable dir",
            "T1059.005",
        ),
        _s("ws_engine", r"//e:(jscript|vbscript)", 20, "forced script engine", "T1059.005"),
    ],
    "cscript": [
        _s(
            "ws_userdir",
            r"(\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\)[^\s\"]*\.(js|jse|vbs|vbe|wsf)",
            35,
            "script from user-writable dir",
            "T1059.005",
        ),
        _s("ws_engine", r"//e:(jscript|vbscript)", 20, "forced script engine", "T1059.005"),
    ],
    "mshta": [
        _s("mshta_url", r"https?://", 55, "remote HTA", "T1218.005", "T1105"),
        _s("mshta_script", r"(javascript|vbscript):", 55, "inline script", "T1218.005"),
        _s(
            "mshta_tmp",
            r"(\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\)[^\s\"]*\.hta",
            30,
            "HTA from user dir",
            "T1218.005",
        ),
    ],
    "rundll32": [
        _s("rd_js", r"javascript:", 60, "inline script", "T1218.011"),
        _s("rd_minidump", r"comsvcs(\.dll)?\s*,\s*#?(minidump|24)", 80, "LSASS minidump", "T1003.001"),
        _s("rd_url", r"url\.dll\s*,\s*(openurl|fileprotocolhandler)", 30, "url.dll proxy", "T1218.011"),
        _s(
            "rd_tmpdll",
            r"(\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\)[^\s\",]*\.(dll|ocx|cpl)",
            35,
            "DLL from user dir",
            "T1218.011",
        ),
        _s(
            "rd_advpack",
            r"(ie)?advpack\.dll\s*,\s*(launchinfsection|regisocx)",
            40,
            "advpack proxy exec",
            "T1218.011",
        ),
        _s("rd_noargs", r"^\s*\"?[^\s\"]*rundll32(\.exe)?\"?\s*$", 30, "rundll32 without arguments", "T1055"),
    ],
    "regsvr32": [
        _s("rs_remote", r"/i:https?://|scrobj\.dll", 65, "Squiblydoo scriptlet", "T1218.010"),
        _s("rs_sct", r"\.sct\b", 40, "scriptlet", "T1218.010"),
        _s(
            "rs_tmpdll",
            r"(\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\)[^\s\"]*\.(dll|ocx)",
            30,
            "DLL from user dir",
            "T1218.010",
        ),
        _s("rs_silent", r"/s\b.*/u\b.*/i|/u\b.*/s\b.*/i", 25, "silent unregister+install", "T1218.010"),
    ],
    "certutil": [
        _s(
            "cu_download",
            r"-(urlcache|urlcachesplit|verifyctl)\b.*https?://|https?://.*-(urlcache|split)",
            55,
            "download",
            "T1105",
        ),
        _s("cu_decode", r"-(decode|decodehex)\b", 30, "decode payload", "T1140"),
        _s("cu_encode", r"-encode\b", 15, "encode data", "T1027"),
    ],
    "bitsadmin": [
        _s("ba_transfer", r"/(transfer|addfile|create)\b", 25, "BITS job", "T1197"),
        _s("ba_url", r"https?://", 25, "remote URL", "T1105"),
        _s("ba_notify", r"/setnotifycmdline", 50, "BITS notify command (persistence)", "T1197"),
    ],
    "wmic": [
        _s("wm_create", r"process\s+call\s+create", 40, "remote/local process creation", "T1047"),
        _s("wm_node", r"/node:", 35, "remote WMI", "T1047", "T1021"),
        _s("wm_shadow", r"shadowcopy", 50, "shadow copy manipulation", "T1490"),
        _s("wm_xsl", r"/format:.*(https?://|\.xsl)", 60, "XSL script processing", "T1220"),
    ],
    "bash": [
        _s("sh_devtcp", r"/dev/(tcp|udp)/", 80, "reverse shell via /dev/tcp", "T1059.004", "T1095"),
        _s(
            "sh_pipe",
            r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b",
            60,
            "download piped to shell",
            "T1105",
            "T1059.004",
        ),
        _s(
            "sh_b64",
            r"base64\s+(-d|--decode)[^|]*\|\s*(ba)?sh",
            55,
            "decoded payload piped to shell",
            "T1140",
        ),
        _s("sh_fifo", r"mkfifo[^;&|]*(;|&&|\|).*\b(nc|ncat|netcat)\b", 70, "fifo reverse shell", "T1059.004"),
        _s(
            "sh_chmod_tmp",
            r"chmod\s+(\+x|[0-7]*[1357][0-7]*)\s+/(tmp|dev/shm|var/tmp)/",
            35,
            "chmod +x in temp dir",
            "T1222.002",
        ),
        _s(
            "sh_histclear",
            r"history\s+-c|unset\s+histfile|histfile=/dev/null|histsize=0|rm\s+-rf?\s+[^;]*\.bash_history",
            30,
            "history tampering",
            "T1070.003",
        ),
    ],
    "curl": [
        _s("dl_tmp", r"(-o|-O|--output)\s*=?\s*/(tmp|dev/shm|var/tmp)/", 35, "download to temp dir", "T1105"),
        _s("dl_rawip", r"https?://\d{1,3}(\.\d{1,3}){3}", 25, "URL with raw IP", "T1105"),
        _s("dl_insecure", r"\s(-k|--insecure)\b", 8, "TLS verification disabled"),
        _s(
            "dl_upload",
            r"(--upload-file|-T\s|--data-binary\s+@|-F\s+\S+=@|-d\s+@)",
            35,
            "file upload (exfil)",
            "T1048",
        ),
        _s(
            "dl_paste",
            r"pastebin|transfer\.sh|file\.io|anonfiles|ngrok|\.onion|raw\.githubusercontent|discord(app)?\.com/api/webhooks",
            15,
            "paste/file-share/tunnel host",
            "T1567",
        ),
    ],
    "wget": [
        _s(
            "dl_tmp",
            r"(-O|-P|--output-document|--directory-prefix)\s*=?\s*/(tmp|dev/shm|var/tmp)",
            35,
            "download to temp dir",
            "T1105",
        ),
        _s("dl_pipe", r"-O-?\s.*\|\s*(ba)?sh|-qO-\s*\S+\s*\|", 55, "download piped to shell", "T1105"),
        _s("dl_rawip", r"https?://\d{1,3}(\.\d{1,3}){3}", 25, "URL with raw IP", "T1105"),
        _s("dl_insecure", r"--no-check-certificate", 8, "TLS verification disabled"),
        _s(
            "dl_paste",
            r"pastebin|transfer\.sh|file\.io|anonfiles|ngrok|\.onion|raw\.githubusercontent",
            15,
            "paste/file-share/tunnel host",
            "T1567",
        ),
    ],
    "python": [
        _s(
            "py_revshell",
            rf"(socket.*(connect|dup2).*(pty|subprocess|/bin/(ba)?sh))|(pty\.spawn)|({_INTERP_SOCK}.*socket.*connect)",
            75,
            "reverse-shell one-liner",
            "T1059.006",
            "T1095",
        ),
        _s(
            "py_b64exec",
            r"(exec|eval)\s*\(.*b64decode|b64decode.*(exec|eval)|exec\(base64",
            50,
            "base64 decode + exec",
            "T1027",
            "T1140",
        ),
        _s(
            "py_urlexec",
            r"(urlopen|requests\.get)\(.*\)\.(read|text|content).*(exec|eval)|exec\(.*(urlopen|requests)",
            45,
            "remote code exec",
            "T1105",
        ),
        _s(
            "py_httpserver",
            r"-m\s+(http\.server|SimpleHTTPServer)",
            12,
            "ad-hoc file server (staging)",
            "T1105",
        ),
    ],
    "perl": [
        _s(
            "pl_revshell",
            r"-e\s.*(socket|io::socket).*(open|exec|system|/bin/(ba)?sh)",
            70,
            "reverse-shell one-liner",
            "T1059",
        ),
        _s("pl_b64", r"decode_base64.*eval|eval.*decode_base64", 45, "base64 decode + eval", "T1027"),
    ],
    "nc": [
        _s(
            "nc_exec",
            r"\s-(e|c)\s+\S*(ba|z|da)?sh\b|--(sh-)?exec",
            85,
            "bind/reverse shell (-e/-c)",
            "T1059.004",
            "T1095",
        ),
        _s("nc_listen", r"\s-[a-z]*l[a-z]*\s|\s--listen", 35, "listener", "T1095"),
        _s("nc_remote", r"\s\S+\s+\d{2,5}\s*$", 12, "outbound connection", "T1095"),
    ],
    "socat": [
        _s("sc_exec", r"\b(exec|system):", 65, "exec/system address", "T1059.004", "T1095"),
        _s("sc_listen", r"tcp[46]?-listen|openssl-listen", 30, "listener", "T1095"),
        _s("sc_pty", r"\bpty\b", 25, "pty allocation (interactive shell)", "T1059.004"),
    ],
}
CMD_SIGNALS["sh"] = CMD_SIGNALS["bash"]
