"""Alert forwarding: send PRISM's attack chains to a SIEM.

Whenever an attack chain appears or changes (more events, a new stage, a new
current host or top prediction), one alert is sent to each configured target:

* a webhook (any URL that accepts JSON: SOAR tools, Teams/Slack bridges, ...)
* Splunk HTTP Event Collector (sourcetype ``prism:attack_chain``)
* syslog in CEF format (QRadar, ArcSight, Microsoft Sentinel, most SIEMs)

Sending happens on a background thread, so a slow or unreachable SIEM never
holds up the analysis. Nothing is sent unless a target is configured.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import urllib.request
from datetime import datetime, timezone
from typing import Any

from app.core.config import ForwardSettings
from app.core.local_only import target_is_local, url_is_local
from app.core.logging_config import get_logger
from app.models.analysis import AttackChain

logger = get_logger(__name__)

SEVERITY_TO_CEF = {"low": 3, "medium": 5, "high": 8, "critical": 10}


def chain_alert(chain: AttackChain, version: str) -> dict[str, Any]:
    """The alert sent for one chain: what a SOC needs to triage it elsewhere."""
    top = chain.predictions[0] if chain.predictions else None
    return {
        "source": "PRISM",
        "version": version,
        "type": "attack_chain",
        "chain_id": chain.attack_chain_id,
        "name": chain.name,
        "status": chain.status,
        "severity": str(getattr(chain.severity, "value", chain.severity)),
        "risk_score": chain.risk_score,
        "confidence": str(getattr(getattr(chain, "confidence", ""), "value", getattr(chain, "confidence", ""))),
        "initial_host": chain.initial_host,
        "current_host": chain.current_host,
        "current_stage": chain.current_stage,
        "hosts": list(chain.hosts),
        "targeted_hosts": list(chain.targeted_hosts),
        "users": list(chain.users),
        "event_count": chain.event_count,
        "first_seen": chain.start_time.isoformat() if chain.start_time else None,
        "last_seen": chain.last_seen.isoformat() if chain.last_seen else None,
        "mitre_techniques": sorted({m.technique_id for m in chain.mitre}),
        "lateral_movements": [
            {"from": m.source_host, "to": m.destination_host, "method": m.method, "assurance": "inferred"}
            for m in chain.lateral_movements
        ],
        "predicted_next_target": (
            {"host": top.host, "score": top.score, "assurance": "predicted"} if top else None
        ),
    }


def _cef_escape(value: Any, header: bool = False) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\")
    if header:
        return text.replace("|", "\\|")
    return text.replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def to_cef(alert: dict[str, Any]) -> str:
    """ArcSight Common Event Format line for one alert."""
    severity = SEVERITY_TO_CEF.get(alert["severity"].lower(), 5)
    target = alert.get("predicted_next_target") or {}
    extension = {
        "rt": int(datetime.now(tz=timezone.utc).timestamp() * 1000),
        "shost": alert.get("initial_host"),
        "dhost": alert.get("current_host"),
        "suser": ",".join(alert.get("users") or []),
        "cnt": alert.get("event_count"),
        "cs1Label": "stage",
        "cs1": alert.get("current_stage"),
        "cs2Label": "nextTarget",
        "cs2": "{} ({})".format(target.get("host"), target.get("score")) if target else "",
        "cs3Label": "mitre",
        "cs3": ",".join(alert.get("mitre_techniques") or []),
        "cn1Label": "riskScore",
        "cn1": alert.get("risk_score"),
        "externalId": alert.get("chain_id"),
    }
    header = "|".join(
        _cef_escape(part, header=True)
        for part in ("CEF:0", "PRISM", "PRISM", alert.get("version", ""), "attack_chain",
                     "{}: {}".format(alert["chain_id"], alert.get("name", "")), severity)
    )
    return header + "|" + " ".join("{}={}".format(k, _cef_escape(v)) for k, v in extension.items() if v not in (None, ""))


class Forwarder:
    """Tracks what was already sent and pushes changed chains to the targets."""

    def __init__(self, settings: ForwardSettings, version: str, local_only: bool = True) -> None:
        self.version = version
        self.blocked: list[str] = []
        if local_only:
            # Local-only mode: alerts may only go to programs on this computer.
            settings = settings.model_copy()
            for name, value, check in (
                ("webhook", settings.webhook_url, url_is_local),
                ("splunk_hec", settings.splunk_hec_url, url_is_local),
                ("syslog_cef", settings.syslog_target, target_is_local),
            ):
                if value and not check(value):
                    self.blocked.append(name)
                    logger.warning("local-only mode: alert target blocked", extra={"target": name})
            if "webhook" in self.blocked:
                settings.webhook_url = ""
            if "splunk_hec" in self.blocked:
                settings.splunk_hec_url = ""
            if "syslog_cef" in self.blocked:
                settings.syslog_target = ""
        self.settings = settings
        self._sent_signatures: dict[str, tuple[Any, ...]] = {}
        self._seen_once: set[str] = set()
        self._lock = threading.Lock()
        self.sent = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_sent_at: datetime | None = None

    @property
    def enabled(self) -> bool:
        s = self.settings
        return bool(s.webhook_url or s.splunk_hec_url or s.syslog_target)

    @staticmethod
    def _signature(chain: AttackChain) -> tuple[Any, ...]:
        top = chain.predictions[0].host if chain.predictions else None
        return (chain.event_count, chain.current_stage, chain.current_host, chain.status, top)

    def notify(self, chains: list[AttackChain]) -> list[dict[str, Any]]:
        """Queue alerts for new or changed chains; returns the alerts queued."""
        if not self.enabled:
            return []
        alerts: list[dict[str, Any]] = []
        with self._lock:
            for chain in chains:
                if chain.risk_score < self.settings.min_risk_score:
                    continue
                signature = self._signature(chain)
                if self._sent_signatures.get(chain.attack_chain_id) == signature:
                    continue
                self._sent_signatures[chain.attack_chain_id] = signature
                if self.settings.format == "ocsf":
                    from app.ocsf import chain_to_finding

                    alert = chain_to_finding(chain, self.version, activity_id=2 if chain.attack_chain_id in self._seen_once else 1)
                    alert["severity"] = str(chain.severity)  # used for CEF severity and routing
                    alert["chain_id"] = chain.attack_chain_id
                else:
                    alert = chain_alert(chain, self.version)
                self._seen_once.add(chain.attack_chain_id)
                alerts.append(alert)
        if alerts:
            threading.Thread(target=self._deliver, args=(alerts,), daemon=True).start()
        return alerts

    def reset(self) -> None:
        with self._lock:
            self._sent_signatures.clear()

    # ------------------------------------------------------------ delivery --

    def _deliver(self, alerts: list[dict[str, Any]]) -> None:
        for alert in alerts:
            for name, send in (
                ("webhook", self._webhook),
                ("splunk_hec", self._splunk),
                ("syslog", self._syslog),
            ):
                try:
                    if send(alert):
                        with self._lock:
                            self.sent += 1
                            self.last_sent_at = datetime.now(tz=timezone.utc)
                except Exception as exc:  # noqa: BLE001 - a broken target must not stop the others
                    with self._lock:
                        self.failed += 1
                        self.last_error = "{}: {}".format(name, exc)
                    logger.warning("alert forwarding failed", extra={"target": name, "error": str(exc)})

    def _post(self, url: str, body: bytes, headers: dict[str, str]) -> None:
        request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", **headers})
        context = None if self.settings.tls_verify else ssl._create_unverified_context()  # noqa: S323 - opt-in
        with urllib.request.urlopen(request, timeout=self.settings.timeout_seconds, context=context) as response:
            response.read()

    def _webhook(self, alert: dict[str, Any]) -> bool:
        if not self.settings.webhook_url:
            return False
        self._post(self.settings.webhook_url, json.dumps(alert).encode("utf-8"), {})
        return True

    def _splunk(self, alert: dict[str, Any]) -> bool:
        if not self.settings.splunk_hec_url:
            return False
        payload = {
            "time": datetime.now(tz=timezone.utc).timestamp(),
            "host": "prism",
            "source": "prism",
            "sourcetype": "prism:attack_chain",
            "event": alert,
        }
        headers = {"Authorization": "Splunk " + self.settings.splunk_hec_token} if self.settings.splunk_hec_token else {}
        self._post(self.settings.splunk_hec_url, json.dumps(payload).encode("utf-8"), headers)
        return True

    def _syslog(self, alert: dict[str, Any]) -> bool:
        if not self.settings.syslog_target:
            return False
        host, _, port = self.settings.syslog_target.rpartition(":")
        severity = SEVERITY_TO_CEF.get(alert["severity"].lower(), 5)
        pri = 8 * 4 + (2 if severity >= 8 else 4)  # facility auth(4); critical or warning
        message = "<{}>{} prism PRISM: {}".format(pri, datetime.now().strftime("%b %d %H:%M:%S"), to_cef(alert))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode("utf-8"), (host or "127.0.0.1", int(port)))
        return True

    def status(self) -> dict[str, Any]:
        s = self.settings
        return {
            "enabled": self.enabled,
            "targets": [name for name, on in (("webhook", s.webhook_url), ("splunk_hec", s.splunk_hec_url), ("syslog_cef", s.syslog_target)) if on],
            "alerts_sent": self.sent,
            "failures": self.failed,
            "last_error": self.last_error,
            "last_sent_at": self.last_sent_at,
            "chains_tracked": len(self._sent_signatures),
            "blocked_by_local_only": list(self.blocked),
        }
