"""Transparent MITRE ATT&CK mapping layer.

Techniques are never assigned by keyword soup. Every mapping is a named rule
with a predicate, an evidence string built from the actual event, and a plain
English explanation of why the rule fired. If a rule cannot explain itself it
does not belong here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.models.analysis import Assurance, Confidence, MitreMapping
from app.models.events import Action, NormalizedEvent

ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"

#: MITRE tactic ids in kill-chain order; used to sort attack-chain stages.
TACTIC_ORDER: dict[str, int] = {
    "TA0043": 0,   # Reconnaissance
    "TA0042": 1,   # Resource Development
    "TA0001": 2,   # Initial Access
    "TA0002": 3,   # Execution
    "TA0003": 4,   # Persistence
    "TA0004": 5,   # Privilege Escalation
    "TA0005": 6,   # Defense Evasion
    "TA0006": 7,   # Credential Access
    "TA0007": 8,   # Discovery
    "TA0008": 9,   # Lateral Movement
    "TA0009": 10,  # Collection
    "TA0011": 11,  # Command and Control
    "TA0010": 12,  # Exfiltration
    "TA0040": 13,  # Impact
}

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _findings(event: NormalizedEvent) -> list[str]:
    """The human-readable findings the normalizer attached to an event."""
    return [t.split("finding:", 1)[1] for t in event.tags if t.startswith("finding:")]


#: Path fragments matched against command lines, kept as constants so the
#: rules below stay free of escape-sensitive literals.
BACKSLASH = chr(92)
SAM_HIVE_PATH = "hklm" + BACKSLASH + "sam"
REG_SAVE = "reg.exe save"
TEMP_DIR_FRAGMENT = BACKSLASH + "temp" + BACKSLASH


def _temp_staged_path(event: NormalizedEvent) -> str | None:
    """Return the path that shows tooling being staged in a temp directory.

    Executing *from* a temp directory counts, as does writing an executable or
    script there. A document landing in Temp does not; that is ordinary mail
    client behaviour.
    """
    image = str(event.raw.get("Image") or "")
    if TEMP_DIR_FRAGMENT in image.lower():
        return image
    dropped = str(event.raw.get("TargetFilename") or "")
    if TEMP_DIR_FRAGMENT in dropped.lower() and dropped.lower().endswith(
        (".exe", ".dll", ".hta", ".ps1", ".bat", ".cmd", ".scr", ".vbs", ".js")
    ):
        return dropped
    return None


def _cmd(event: NormalizedEvent) -> str:
    return (event.command_line or "").lower()


@dataclass(frozen=True)
class MitreRule:
    """One auditable technique-assignment rule."""

    technique_id: str
    technique_name: str
    tactic_id: str
    confidence: Confidence
    explanation: str
    matches: Callable[[NormalizedEvent], bool]
    evidence: Callable[[NormalizedEvent], str]

    @property
    def tactic(self) -> str:
        return TACTIC_NAMES.get(self.tactic_id, self.tactic_id)

    def apply(self, event: NormalizedEvent) -> MitreMapping | None:
        if not self.matches(event):
            return None
        return MitreMapping(
            technique_id=self.technique_id,
            technique_name=self.technique_name,
            tactic_id=self.tactic_id,
            tactic=self.tactic,
            event_id=event.event_id,
            evidence=self.evidence(event),
            explanation=self.explanation,
            confidence=self.confidence,
            assurance=Assurance.OBSERVED,
            reference=ATTACK_BASE_URL + self.technique_id.replace(".", "/") + "/",
        )


RULES: list[MitreRule] = [
    MitreRule(
        technique_id="T1566.001",
        technique_name="Phishing: Spearphishing Attachment",
        tactic_id="TA0001",
        confidence=Confidence.HIGH,
        explanation=(
            "A mail or Office process wrote a macro/script-bearing document to disk, "
            "which is how attachment-delivered intrusions begin."
        ),
        matches=lambda e: e.action is Action.MALICIOUS_ATTACHMENT and "file-create" in e.tags,
        evidence=lambda e: "{} wrote {} on {}".format(
            e.process or "mail client", e.file_name or "an attachment", e.primary_host
        ),
    ),
    MitreRule(
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
        tactic_id="TA0002",
        confidence=Confidence.HIGH,
        explanation="The user opened the delivered document, which is what triggers the payload.",
        matches=lambda e: e.action is Action.MALICIOUS_ATTACHMENT and "file-create" not in e.tags,
        evidence=lambda e: "{} opened on {} by {}".format(
            e.process or "document", e.primary_host, e.user or "unknown user"
        ),
    ),
    MitreRule(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic_id="TA0002",
        confidence=Confidence.HIGH,
        explanation=(
            "PowerShell executed on the host, in a parent/child or flag pattern "
            "typical of payload execution."
        ),
        matches=lambda e: e.action is Action.POWERSHELL_EXEC,
        evidence=lambda e: "{} executed on {}{}".format(
            e.process or "powershell.exe",
            e.primary_host,
            " (parent: " + e.parent_process + ")" if e.parent_process else "",
        ),
    ),
    MitreRule(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic_id="TA0005",
        confidence=Confidence.MEDIUM,
        explanation=(
            "The command line was encoded or hidden, which is done to defeat log "
            "review and signature matching."
        ),
        matches=lambda e: any(
            frag in _cmd(e) for frag in ("-enc", "-encodedcommand", "hidden", "frombase64string")
        ),
        evidence=lambda e: "Command line on {}: {}".format(e.primary_host, (e.command_line or "")[:160]),
    ),
    MitreRule(
        technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        tactic_id="TA0002",
        confidence=Confidence.MEDIUM,
        explanation="A command shell ran a child command, usually as part of hands-on-keyboard activity.",
        matches=lambda e: e.action is Action.COMMAND_EXEC,
        evidence=lambda e: "{} on {}: {}".format(
            e.process or "cmd.exe", e.primary_host, (e.command_line or "")[:160]
        ),
    ),
    MitreRule(
        technique_id="T1033",
        technique_name="System Owner/User Discovery",
        tactic_id="TA0007",
        confidence=Confidence.MEDIUM,
        explanation=(
            "The account enumerated its own identity and privileges, a standard "
            "first post-compromise step."
        ),
        matches=lambda e: "whoami" in _cmd(e),
        evidence=lambda e: "Identity enumeration on {}: {}".format(
            e.primary_host, (e.command_line or "")[:120]
        ),
    ),
    MitreRule(
        technique_id="T1069.002",
        technique_name="Permission Groups Discovery: Domain Groups",
        tactic_id="TA0007",
        confidence=Confidence.MEDIUM,
        explanation=(
            "Domain group membership was enumerated, which is how an attacker "
            "finds privileged accounts to target."
        ),
        matches=lambda e: "net group" in _cmd(e) or "net localgroup" in _cmd(e),
        evidence=lambda e: "Group enumeration on {}: {}".format(
            e.primary_host, (e.command_line or "")[:120]
        ),
    ),
]

RULES += [
    MitreRule(
        technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
        tactic_id="TA0006",
        confidence=Confidence.HIGH,
        explanation="A process read or dumped LSASS memory, where Windows keeps credential material.",
        matches=lambda e: e.action is Action.CREDENTIAL_ACCESS
        and ("lsass" in _cmd(e) or any("lsass" in f.lower() for f in _findings(e))),
        evidence=lambda e: "; ".join(_findings(e)) or "LSASS access on {}".format(e.primary_host),
    ),
    MitreRule(
        technique_id="T1003.002",
        technique_name="OS Credential Dumping: Security Account Manager",
        tactic_id="TA0006",
        confidence=Confidence.HIGH,
        explanation=(
            "The SAM/SECURITY registry hives were exported, yielding "
            "offline-crackable local credentials."
        ),
        matches=lambda e: e.action is Action.CREDENTIAL_ACCESS
        and (SAM_HIVE_PATH in _cmd(e) or REG_SAVE in _cmd(e)),
        evidence=lambda e: "Registry hive export on {}: {}".format(
            e.primary_host, (e.command_line or "")[:140]
        ),
    ),
    MitreRule(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_id="TA0006",
        confidence=Confidence.MEDIUM,
        explanation=(
            "Several failed logons for one account in a short window indicate "
            "credential guessing or replay attempts."
        ),
        matches=lambda e: e.action is Action.LOGIN_FAILURE and "credential-guessing" in e.tags,
        evidence=lambda e: "; ".join(_findings(e))
        or "Failed logon for {} against {}".format(e.user, e.destination_host),
    ),
    MitreRule(
        technique_id="T1021.001",
        technique_name="Remote Services: Remote Desktop Protocol",
        tactic_id="TA0008",
        confidence=Confidence.HIGH,
        explanation="An interactive RDP session was established from one host to another using the same account.",
        matches=lambda e: e.action is Action.RDP_LOGIN
        and bool(e.source_host)
        and bool(e.destination_host)
        and e.source_host != e.destination_host,
        evidence=lambda e: "RDP logon by {} from {} to {}".format(
            e.user, e.source_host, e.destination_host
        ),
    ),
    MitreRule(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic_id="TA0008",
        confidence=Confidence.HIGH,
        explanation=(
            "An administrative share was mounted across the network, a common "
            "staging step for remote execution."
        ),
        matches=lambda e: e.action is Action.SMB_AUTH and "admin-share" in e.tags,
        evidence=lambda e: "Admin share access by {} from {} to {}".format(
            e.user, e.source_host, e.destination_host
        ),
    ),
    MitreRule(
        technique_id="T1569.002",
        technique_name="System Services: Service Execution",
        tactic_id="TA0002",
        confidence=Confidence.HIGH,
        explanation=(
            "A remote-execution service utility was run or installed, which "
            "executes code on another host."
        ),
        matches=lambda e: e.action is Action.REMOTE_SERVICE_EXEC,
        evidence=lambda e: "{} on {}{}".format(
            e.process or "service utility",
            e.primary_host,
            ": " + (e.command_line or "")[:120] if e.command_line else "",
        ),
    ),
    MitreRule(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic_id="TA0008",
        confidence=Confidence.HIGH,
        explanation=(
            "A remote-execution utility was pointed at another host by UNC path, "
            "so the command executes on that host rather than locally."
        ),
        matches=lambda e: e.action is Action.REMOTE_SERVICE_EXEC
        and (BACKSLASH + BACKSLASH) in (e.command_line or ""),
        evidence=lambda e: "{} targeted a remote host from {}: {}".format(
            e.process or "remote-exec utility", e.primary_host, (e.command_line or "")[:120]
        ),
    ),
    MitreRule(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_id="TA0004",
        confidence=Confidence.MEDIUM,
        explanation=(
            "A logon was granted elevated privileges, so the attacker is "
            "operating with legitimate credentials."
        ),
        matches=lambda e: e.action is Action.PRIVILEGED_LOGIN,
        evidence=lambda e: "Privileged logon for {} on {}".format(e.user, e.primary_host),
    ),
    MitreRule(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        tactic_id="TA0011",
        confidence=Confidence.HIGH,
        explanation=(
            "The host resolved external infrastructure flagged by threat intel or "
            "heuristics, consistent with command and control."
        ),
        matches=lambda e: e.action is Action.SUSPICIOUS_DOMAIN,
        evidence=lambda e: "{} resolved {} ({})".format(
            e.source_host, e.domain, "; ".join(_findings(e)) or "flagged domain"
        ),
    ),
    MitreRule(
        technique_id="T1568.002",
        technique_name="Dynamic Resolution: Domain Generation Algorithms",
        tactic_id="TA0011",
        confidence=Confidence.MEDIUM,
        explanation="A high-entropy domain label was queried, which is how DGA-based C2 rotates infrastructure.",
        matches=lambda e: any("DGA" in f for f in _findings(e)),
        evidence=lambda e: "{} queried {}".format(e.source_host, e.domain),
    ),
    MitreRule(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic_id="TA0011",
        confidence=Confidence.MEDIUM,
        explanation="Repeated lookups for one domain at a regular cadence are the signature of beaconing.",
        matches=lambda e: "beaconing" in e.tags and e.action is not Action.SUSPICIOUS_DOMAIN,
        evidence=lambda e: "; ".join(_findings(e)) or "Repeated lookups for {}".format(e.domain),
    ),
    MitreRule(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic_id="TA0011",
        confidence=Confidence.MEDIUM,
        explanation=(
            "A binary was written into or executed from a temporary directory, "
            "indicating the attacker staged their own tooling."
        ),
        matches=lambda e: _temp_staged_path(e) is not None,
        evidence=lambda e: "Staged tooling on {}: {}".format(e.primary_host, _temp_staged_path(e)),
    ),
]


def map_event(event: NormalizedEvent) -> list[MitreMapping]:
    """Return every technique that legitimately applies to one event."""
    mappings: list[MitreMapping] = []
    seen: set[str] = set()
    for rule in RULES:
        mapping = rule.apply(event)
        if mapping is None or mapping.technique_id in seen:
            continue
        seen.add(mapping.technique_id)
        mappings.append(mapping)
    return mappings


def map_events(events: list[NormalizedEvent]) -> list[MitreMapping]:
    """Map a batch of events, preserving chronological order."""
    mappings: list[MitreMapping] = []
    for event in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        mappings.extend(map_event(event))
    return mappings


def primary_tactic(mappings: list[MitreMapping]) -> str | None:
    """The furthest-along tactic in a set of mappings."""
    if not mappings:
        return None
    return max(mappings, key=lambda m: TACTIC_ORDER.get(m.tactic_id, -1)).tactic
