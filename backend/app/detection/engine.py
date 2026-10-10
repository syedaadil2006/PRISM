"""The detection layer that runs during normalization, on top of PRISM's own rules.

Four things, each explainable and each reversible:

1. **Sigma rules** (app/detection/sigma.py) - a match marks the event
   suspicious (medium level and above), raises its severity to the rule's level,
   attaches the rule's ATT&CK techniques and adds a finding naming the rule.
2. **Threat intelligence** (app/detection/intel.py) - a known-bad domain, IP,
   hash or URL marks the event suspicious (high) with the indicator's source.
3. **Analyst feedback** - a chain marked *false positive* becomes suppression
   entries (same action, same program/domain/file, same computer, same
   account); matching events are kept but cannot start or extend a chain, and
   the reason names the analyst. Deleting the entry restores them.
4. **Behaviour baselines** (app/detection/baseline.py) - anomaly evidence.

Rule and indicator results are recorded with a version stamp and the event's
original severity, so reloading rules or intel re-evaluates every event cleanly.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.core.logging_config import get_logger
from app.detection.baseline import apply_baselines, mark_routine
from app.detection.intel import IntelSet, load_intel
from app.detection.sigma import _LOWERED, RuleSet, SigmaRule, event_products, load_rules, logsource_categories
from app.models.events import NormalizedEvent, Severity

logger = get_logger(__name__)

SIGMA_TAG = "sigma:"
INTEL_TAG = "intel:"
BASE_TAG = "det:base="
VERSION_TAG = "det:v="
FEEDBACK_REASON = "analyst: "
LEVEL_SEVERITY = {"informational": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
                  "high": Severity.HIGH, "critical": Severity.CRITICAL}
DETECTION_PREFIXES = (SIGMA_TAG, INTEL_TAG, BASE_TAG, VERSION_TAG, "finding:Sigma: ", "finding:Threat intel: ")


def indicator_of(event: NormalizedEvent) -> str:
    """What the event is about: the program, domain or file (lower case)."""
    return (event.process or event.domain or event.file_name or "").lower()


def suppression_key(event: NormalizedEvent) -> tuple[str, str, str, str]:
    return (event.action.value, indicator_of(event), (event.primary_host or "").upper(), (event.user or "").lower())


@dataclass
class Suppression:
    id: str
    action: str
    indicator: str
    host: str
    user: str
    chain_id: str
    analyst: str
    note: str
    created_at: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.action, self.indicator, self.host, self.user)


@dataclass
class Detections:
    rules: RuleSet = field(default_factory=RuleSet)
    intel: IntelSet = field(default_factory=IntelSet)
    suppressions: dict[str, Suppression] = field(default_factory=dict)
    verdicts: list[dict[str, str]] = field(default_factory=list)
    baseline_enabled: bool = True
    baseline_min_history: int = 20
    baseline_learning_hours: float = 24.0
    baseline_routine_days: int = 3
    version: str = "0"
    _rule_index: dict[str, SigmaRule] = field(default_factory=dict)
    #: Rules grouped by log-source category (None = any), so each event is only
    #: checked against rules written for its kind of log.
    _by_category: dict[str | None, list[SigmaRule]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def reindex(self) -> None:
        self._rule_index = self.rules.by_id()
        self._by_category = {}
        for rule in self.rules.rules:
            self._by_category.setdefault(rule.category, []).append(rule)
        fingerprint = json.dumps([sorted(self._rule_index), sorted(self.intel.domains), sorted(self.intel.ips),
                                  sorted(self.intel.hashes), sorted(self.intel.urls)])
        self.version = hashlib.sha256(fingerprint.encode()).hexdigest()[:12]

    def rule(self, rule_id: str) -> SigmaRule | None:
        return self._rule_index.get(rule_id)

    # ------------------------------------------------------------ per event --

    def _evaluate(self, event: NormalizedEvent) -> None:
        stamp = VERSION_TAG + self.version
        if stamp in event.tags:
            return
        base = next((t for t in event.tags if t.startswith(BASE_TAG)), None)
        if base:  # undo the previous evaluation
            severity, suspicious = base[len(BASE_TAG):].split("|")
            event.severity, event.suspicious = Severity(severity), suspicious == "1"
        event.tags[:] = [t for t in event.tags if not t.startswith(DETECTION_PREFIXES)]
        event.tags.append(f"{BASE_TAG}{event.severity.value}|{int(event.suspicious)}")

        products = event_products(event)
        candidates = list(self._by_category.get(None, []))
        for category in logsource_categories(event):
            candidates.extend(self._by_category.get(category, []))
        for rule in candidates:
            if rule.product and rule.product not in products:
                continue
            try:
                hit = rule.matcher(event)
            except Exception:  # noqa: BLE001 - one odd record must not break detection
                hit = False
            if not hit:
                continue
            event.tags.append(SIGMA_TAG + rule.id)
            event.tags.append(f"finding:Sigma: {rule.title} ({rule.level})")
            rule_severity = LEVEL_SEVERITY[rule.level]
            if rule_severity.rank > event.severity.rank:
                event.severity = rule_severity
            if rule_severity.rank >= Severity.MEDIUM.rank:
                event.suspicious = True

        for indicator in self.intel.match(event):
            event.tags.append(f"{INTEL_TAG}{indicator.kind}:{indicator.value}")
            event.tags.append(f"finding:Threat intel: {indicator.kind} {indicator.value} is listed in "
                              f"{indicator.source} ({indicator.description})")
            event.suspicious = True
            if event.severity.rank < Severity.HIGH.rank:
                event.severity = Severity.HIGH
        event.tags.append(stamp)

    # ------------------------------------------------------------ whole set --

    def apply(self, events: list[NormalizedEvent]) -> None:
        """Run every detection over ``events`` (already in time order)."""
        with self._lock:
            for event in events:
                self._evaluate(event)
            _LOWERED.clear()
            keys = {s.key: s for s in self.suppressions.values()}
            for event in events:
                if event.suppressed and event.suppressed.startswith(FEEDBACK_REASON):
                    event.suppressed = None  # recomputed from the current list
                if keys and not event.suppressed:
                    found = keys.get(suppression_key(event))
                    if found:
                        event.suppressed = (f"{FEEDBACK_REASON}{found.analyst} marked {found.chain_id} a false positive "
                                            f"on {found.created_at[:10]}" + (f": {found.note}" if found.note else ""))
            if self.baseline_enabled:
                apply_baselines(events, self.baseline_min_history, self.baseline_learning_hours)
                mark_routine(events, self.baseline_routine_days)
            else:
                mark_routine(events, 0)  # clears earlier routine marks

    # ------------------------------------------------------------- feedback --

    def add_false_positive(self, chain_id: str, events: list[NormalizedEvent], analyst: str, note: str) -> list[Suppression]:
        created = []
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            for event in events:
                if not (event.suspicious or event.is_notable):
                    continue
                key = suppression_key(event)
                if any(s.key == key for s in self.suppressions.values()):
                    continue
                entry_id = hashlib.sha256("|".join(key).encode()).hexdigest()[:10]
                entry = Suppression(entry_id, *key, chain_id=chain_id, analyst=analyst, note=note, created_at=now)
                self.suppressions[entry_id] = entry
                created.append(entry)
        return created

    def export_feedback(self) -> str:
        return json.dumps({"suppressions": [s.__dict__ for s in self.suppressions.values()],
                           "verdicts": self.verdicts[-500:]})

    def import_feedback(self, text: str | None) -> None:
        if not text:
            return
        data = json.loads(text)
        self.suppressions = {s["id"]: Suppression(**s) for s in data.get("suppressions", [])}
        self.verdicts = list(data.get("verdicts", []))

    def describe(self) -> dict[str, object]:
        return {
            "version": self.version,
            "sigma": {"loaded": len(self.rules.rules), "skipped": len(self.rules.skipped),
                      "skipped_examples": self.rules.skipped[:10]},
            "intel": {"indicators": self.intel.count, "domains": len(self.intel.domains), "ips": len(self.intel.ips),
                      "hashes": len(self.intel.hashes), "urls": len(self.intel.urls), "files": self.intel.files},
            "baseline": {"enabled": self.baseline_enabled, "min_history": self.baseline_min_history,
                         "learning_hours": self.baseline_learning_hours,
                         "routine_days": self.baseline_routine_days},
            "suppressions": len(self.suppressions),
        }


_current: Detections | None = None


def build(settings) -> Detections:  # noqa: ANN001 - DetectionSettings
    detections = Detections(baseline_enabled=settings.baseline_enabled,
                            baseline_min_history=settings.baseline_min_history,
                            baseline_learning_hours=settings.baseline_learning_hours,
                            baseline_routine_days=settings.baseline_routine_days)
    if settings.sigma_enabled:
        detections.rules = load_rules([Path(p) for p in settings.sigma_dirs if Path(p).exists()])
    detections.intel = load_intel([Path(p) for p in settings.intel_dirs])
    detections.reindex()
    logger.info("detections loaded", extra={"sigma_rules": len(detections.rules.rules),
                                            "sigma_skipped": len(detections.rules.skipped),
                                            "indicators": detections.intel.count})
    return detections


def current() -> Detections:
    """The detections in use (built from settings on first use)."""
    global _current
    if _current is None:
        from app.core.config import get_settings

        _current = build(get_settings().detection)
    return _current


def install(detections: Detections) -> None:
    global _current
    _current = detections
