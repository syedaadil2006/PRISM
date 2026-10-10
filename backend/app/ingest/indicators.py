"""Heuristics used during normalization to flag suspicious behaviour.

This is deliberately a small, readable indicator layer rather than an opaque
model: every flag it raises becomes evidence text an analyst can read. Extend
the tuples below to tune detection without touching the parsers.
"""

from __future__ import annotations

import re

#: Interpreters and living-off-the-land binaries abused for execution.
SCRIPT_INTERPRETERS: tuple[str, ...] = (
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
)

#: Tools whose presence indicates credential theft.
CREDENTIAL_TOOLS: tuple[str, ...] = (
    "mimikatz.exe",
    "procdump.exe",
    "lsass",
    "secretsdump.py",
    "ntdsutil.exe",
    "vaultcmd.exe",
    "reg.exe save",
)

#: Remote-execution utilities typically seen during lateral movement.
REMOTE_EXEC_TOOLS: tuple[str, ...] = (
    "psexec.exe",
    "psexesvc.exe",
    "wmic.exe",
    "winrs.exe",
    "paexec.exe",
)

#: Office processes that should not normally spawn interpreters.
OFFICE_PROCESSES: tuple[str, ...] = (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
)

#: Attachment extensions commonly used for initial access.
MALICIOUS_ATTACHMENT_EXTENSIONS: tuple[str, ...] = (
    ".docm",
    ".xlsm",
    ".js",
    ".vbs",
    ".hta",
    ".lnk",
    ".iso",
    ".scr",
)

#: Command-line fragments that indicate obfuscation or remote download.
SUSPICIOUS_COMMAND_FRAGMENTS: tuple[str, ...] = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "bypass",
    "-noni",
)

#: Host and domain enumeration commands. Kept deliberately narrow: these are
#: the ones that are rare in normal user activity but routine for an operator
#: getting their bearings after landing on a machine.
DISCOVERY_COMMANDS: tuple[str, ...] = (
    "whoami /all",
    "whoami /groups",
    "net group",
    "net localgroup",
    "net view",
    "net user",
    "nltest",
    "dsquery",
    "quser",
    "systeminfo",
)


#: TLDs over-represented in commodity C2 infrastructure.
SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz",
    ".top",
    ".tk",
    ".click",
    ".rest",
    ".zip",
    ".cc",
    ".su",
)

#: Domains explicitly on the threat-intel deny list for the demo dataset.
KNOWN_BAD_DOMAINS: tuple[str, ...] = (
    "update-svc-cdn.xyz",
    "cdn-telemetry-sync.top",
    "mail-secure-login.click",
)

#: Internal suffixes that should never be treated as suspicious.
INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".corp.local",
    ".internal",
    "in-addr.arpa",
)

_DGA_RE = re.compile(r"^[a-z0-9]{12,}$")


def is_internal_domain(domain: str) -> bool:
    lowered = domain.lower().rstrip(".")
    # Reverse-DNS lookups and single-label names (NetBIOS / LLMNR broadcasts)
    # are local resolution, not internet destinations.
    if lowered.endswith((".in-addr.arpa", ".ip6.arpa")) or "." not in lowered:
        return True
    return any(lowered.endswith(suffix) or suffix in lowered for suffix in INTERNAL_DOMAIN_SUFFIXES)


def looks_like_dga(domain: str) -> bool:
    """Crude high-entropy label check used to flag algorithmic domains."""
    label = domain.split(".")[0].lower()
    if not _DGA_RE.match(label):
        return False
    digits = sum(c.isdigit() for c in label)
    vowels = sum(c in "aeiou" for c in label)
    return digits >= 2 or vowels <= len(label) // 6


def domain_findings(domain: str) -> list[str]:
    """Return human-readable reasons a domain is suspicious (may be empty)."""
    findings: list[str] = []
    lowered = domain.lower()
    if is_internal_domain(lowered):
        return findings
    if lowered in KNOWN_BAD_DOMAINS:
        findings.append(f"{domain} is on the threat-intel deny list")
    if any(lowered.endswith(tld) for tld in SUSPICIOUS_TLDS):
        findings.append(f"{domain} uses a TLD associated with commodity C2")
    if looks_like_dga(lowered):
        findings.append(f"{domain} has a high-entropy label consistent with DGA")
    return findings


def process_findings(process: str | None, command_line: str | None, parent: str | None) -> list[str]:
    """Return human-readable reasons a process event is suspicious."""
    findings: list[str] = []
    proc = (process or "").lower()
    cmd = (command_line or "").lower()
    par = (parent or "").lower()
    blob = f"{proc} {cmd}"

    if any(tool in blob for tool in CREDENTIAL_TOOLS):
        findings.append("Command touches LSASS or a known credential-dumping tool")
    if any(tool in blob for tool in REMOTE_EXEC_TOOLS):
        findings.append("Remote-execution utility invoked")
    if any(frag in cmd for frag in SUSPICIOUS_COMMAND_FRAGMENTS):
        findings.append("Command line contains obfuscation or remote-download flags")
    if par and any(office in par for office in OFFICE_PROCESSES):
        if any(interp in proc for interp in SCRIPT_INTERPRETERS):
            findings.append(f"Office process {parent} spawned interpreter {process}")
    if any(proc.endswith(ext) for ext in MALICIOUS_ATTACHMENT_EXTENSIONS):
        findings.append("Executed file uses an extension common to malicious attachments")
    if any(ext in cmd for ext in MALICIOUS_ATTACHMENT_EXTENSIONS):
        findings.append("Command line references a suspicious attachment file")
    return findings


def is_interpreter(process: str | None) -> bool:
    proc = (process or "").lower()
    return any(interp in proc for interp in SCRIPT_INTERPRETERS)


def is_credential_activity(process: str | None, command_line: str | None) -> bool:
    blob = f"{(process or '').lower()} {(command_line or '').lower()}"
    return any(tool in blob for tool in CREDENTIAL_TOOLS)


def is_remote_exec(process: str | None, command_line: str | None) -> bool:
    blob = f"{(process or '').lower()} {(command_line or '').lower()}"
    return any(tool in blob for tool in REMOTE_EXEC_TOOLS)


def discovery_findings(command_line: str | None) -> list[str]:
    """Return a finding when a command line performs host/domain enumeration."""
    cmd = (command_line or "").lower()
    hits = [c for c in DISCOVERY_COMMANDS if c in cmd]
    if not hits:
        return []
    return ["Enumeration command executed: " + ", ".join(hits)]


def is_discovery_command(command_line: str | None) -> bool:
    return bool(discovery_findings(command_line))
