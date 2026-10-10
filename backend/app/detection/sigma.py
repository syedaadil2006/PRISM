"""Sigma rule support: load community-format detection rules and match events.

Sigma (https://sigmahq.io) is the open, vendor-neutral format SOC teams use to
share detections. PRISM reads Sigma YAML rules and evaluates them against every
normalized event, on this computer, at ingestion time.

Supported (the parts single-event rules use):

* ``logsource`` by product (windows, linux) and category / service:
  process_creation, process_access, file_event, dns / dns_query,
  network_connection, authentication / security (logons), linux auditd / auth;
* ``detection`` maps and lists of maps, keyword lists, ``null`` values;
* field modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re``,
  ``cidr``, ``exists``, ``windash``, ``cased``, ``gt/gte/lt/lte``;
  ``*`` and ``?`` wildcards;
* conditions with ``and``, ``or``, ``not``, parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them`` and ``all of them``.

Rules that need anything else (aggregations such as ``| count() by``,
correlation rules, base64 modifiers) are skipped and listed with the reason,
never silently half-applied.

Field names are looked up in the original record first (case-insensitive,
with common aliases from ECS and other shippers), then in PRISM's normalized
fields, so standard Windows/Sysmon rules work on PRISM's events.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from app.models.events import Action, EventType, NormalizedEvent

LEVELS = ("informational", "low", "medium", "high", "critical")

#: Sigma field name -> other names the same value goes by in raw records.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "image": ("NewProcessName", "process.executable", "SourceImage"),
    "commandline": ("process.command_line", "ProcessCommandLine"),
    "parentimage": ("ParentProcessName", "process.parent.executable"),
    "parentcommandline": ("process.parent.command_line",),
    "user": ("SubjectUserName", "TargetUserName", "user.name"),
    "computer": ("ComputerName", "host.name", "Hostname"),
    "queryname": ("query", "dns.question.name", "QueryName"),
    "targetfilename": ("file.path", "TargetFilename"),
    "hashes": ("Hashes", "file.hash.sha256"),
    "destinationip": ("id.resp_h", "destination.ip", "DestinationIp"),
    "sourceip": ("id.orig_h", "source.ip", "IpAddress"),
    "destinationport": ("id.resp_p", "destination.port"),
}

#: Normalized fallbacks when the raw record lacks the field.
NORMALIZED: dict[str, Callable[[NormalizedEvent], Any]] = {
    "image": lambda e: "\\" + e.process if e.process else None,
    "originalfilename": lambda e: e.process,
    "commandline": lambda e: e.command_line,
    "parentimage": lambda e: "\\" + e.parent_process if e.parent_process else None,
    "user": lambda e: e.user,
    "targetusername": lambda e: e.user,
    "computer": lambda e: e.destination_host or e.source_host,
    "computername": lambda e: e.destination_host or e.source_host,
    "queryname": lambda e: e.domain,
    "targetfilename": lambda e: e.file_name,
    "logontype": lambda e: e.logon_type,
    "ipaddress": lambda e: e.source_ip,
    "sourceip": lambda e: e.source_ip,
    "destinationip": lambda e: e.destination_ip,
    "workstationname": lambda e: e.source_host,
}


class UnsupportedRule(ValueError):
    pass


def logsource_categories(event: NormalizedEvent) -> set[str]:
    """Which Sigma log sources an event belongs to."""
    tags = set(event.tags)
    cats: set[str] = set()
    if event.event_type is EventType.DNS:
        cats |= {"dns", "dns_query"}
    elif event.event_type is EventType.AUTHENTICATION:
        cats |= {"authentication", "security"}
    else:
        if "sysmon:10" in tags or "process-access" in tags:
            cats.add("process_access")
        elif "file-create" in tags or "sysmon:11" in tags:
            cats.add("file_event")
        else:
            cats.add("process_creation")
    if event.action is Action.REMOTE_SERVICE_EXEC or "sysmon:3" in tags:
        cats.add("network_connection")
    if any(t.startswith(("auditd", "syslog")) for t in tags) or "linux" in event.source_log.lower():
        cats |= {"auditd", "auth", "linux"}
    return cats


def event_products(event: NormalizedEvent) -> set[str]:
    linux = any(t.startswith(("auditd", "syslog")) for t in event.tags) or "linux" in event.source_log.lower()
    return {"linux"} if linux else {"windows"}


#: The lower-cased keys of the record being evaluated (one record at a time per
#: thread), so a few thousand rules do not each rebuild it.
_LOWERED: dict[int, dict[str, Any]] = {}


def _lowered(record: dict[str, Any]) -> dict[str, Any]:
    key = id(record)
    cached = _LOWERED.get(key)
    if cached is None:
        _LOWERED.clear()
        cached = _LOWERED[key] = {str(k).lower(): v for k, v in record.items()}
    return cached


def _lookup(record: dict[str, Any], name: str) -> Any:
    lowered = _lowered(record)
    if name.lower() in lowered:
        return lowered[name.lower()]
    for alias in FIELD_ALIASES.get(name.lower(), ()):
        if alias.lower() in lowered:
            return lowered[alias.lower()]
        value: Any = record  # dotted ECS paths in nested records
        for part in alias.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is not None:
            return value
    return None


def field_value(event: NormalizedEvent, name: str) -> Any:
    value = _lookup(event.raw, name) if event.raw else None
    if value in (None, "", "-") and name.lower() in NORMALIZED:
        value = NORMALIZED[name.lower()](event)
    return value


# --------------------------------------------------------------- matchers --

def sigma_regex(pattern: str) -> str:
    """Sigma wildcards to a regular expression.

    Only ``*`` (any text) and ``?`` (one character) are special; ``\\*``,
    ``\\?`` and ``\\\\`` are literal. Everything else - brackets included - is
    plain text (``fnmatch`` would wrongly read ``[U+202E]`` as a character set).
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    return "".join(out)


def _glob(pattern: str, cased: bool, prefix: str = "", suffix: str = "") -> Callable[[str], bool]:
    """Match a Sigma value; ``prefix``/``suffix`` are the wildcards a modifier adds.

    They are added to the regular expression, after the value is converted, so a
    value ending in a backslash (``\\Temp\\`` with ``contains``) is not misread as
    an escaped ``*``.
    """
    if not cased:
        pattern = pattern.lower()
    if prefix or suffix or any(c in pattern for c in "*?\\"):
        regex = re.compile(prefix + sigma_regex(pattern) + suffix, re.DOTALL)
        return lambda text: bool(regex.fullmatch(text if cased else text.lower()))
    return lambda text: (text if cased else text.lower()) == pattern


def _value_matcher(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    cased = "cased" in modifiers
    if value is None:
        return lambda actual: actual in (None, "", [])
    if "exists" in modifiers:
        want = bool(value)
        return lambda actual: (actual not in (None, "")) == want
    for op, fn in (("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b),
                   ("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b)):
        if op in modifiers:
            limit = float(value)

            def compare(actual: Any, fn=fn, limit=limit) -> bool:
                try:
                    return fn(float(actual), limit)
                except (TypeError, ValueError):
                    return False
            return compare
    if "cidr" in modifiers:
        network = ipaddress.ip_network(str(value), strict=False)

        def in_cidr(actual: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in network
            except ValueError:
                return False
        return in_cidr
    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        regex = re.compile(str(value), flags)
        return lambda actual: actual is not None and bool(regex.search(str(actual)))

    text = str(value)
    variants = [text]
    if "windash" in modifiers:  # -flag also written as /flag (and en/em dashes)
        variants = sorted({text, text.replace("-", "/"), text.replace("-", "–"), text.replace("-", "—")})
    prefix = ".*" if "contains" in modifiers or "endswith" in modifiers else ""
    suffix = ".*" if "contains" in modifiers or "startswith" in modifiers else ""
    tests = [_glob(v, cased, prefix, suffix) for v in variants]

    def match(actual: Any) -> bool:
        if actual is None:
            return False
        items = actual if isinstance(actual, list) else [actual]
        return any(test(str(item)) for item in items for test in tests)
    return match


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists", "windash", "cased",
                       "gt", "gte", "lt", "lte", "i", "m", "s"}


def _field_matcher(key: str, values: Any) -> Callable[[NormalizedEvent], bool]:
    name, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedRule("modifier " + ", ".join(sorted(unknown)))
    values = values if isinstance(values, list) else [values]
    matchers = [_value_matcher(v, modifiers) for v in values]
    require_all = "all" in modifiers

    def match(event: NormalizedEvent) -> bool:
        actual = field_value(event, name)
        results = (m(actual) for m in matchers)
        return all(results) if require_all else any(results)
    return match


def _selection(spec: Any) -> Callable[[NormalizedEvent], bool]:
    if isinstance(spec, dict):
        parts = [_field_matcher(k, v) for k, v in spec.items()]
        return lambda e: all(p(e) for p in parts)
    if isinstance(spec, list) and spec and all(isinstance(s, dict) for s in spec):
        options = [_selection(s) for s in spec]
        return lambda e: any(o(e) for o in options)
    if isinstance(spec, (list, str)):  # keywords: search every value of the record
        words = [str(w).lower() for w in (spec if isinstance(spec, list) else [spec])]

        def keywords(event: NormalizedEvent) -> bool:
            haystack = " ".join(str(v) for v in event.raw.values()).lower() + " " + (event.command_line or "").lower()
            return any(w.strip("*") in haystack for w in words)
        return keywords
    raise UnsupportedRule("selection shape")


# -------------------------------------------------------------- condition --

_TOKEN = re.compile(r"\s*(\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+)", re.IGNORECASE)


def _compile_condition(text: str, selections: dict[str, Callable[[NormalizedEvent], bool]]):
    if "|" in text:
        raise UnsupportedRule("aggregation in condition")
    tokens = [t.lower() if t.lower() in {"and", "or", "not", "1 of", "all of"} else t
              for t in _TOKEN.findall(text)]
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        position += 1
        return tokens[position - 1]

    def names(pattern: str) -> list[Callable]:
        found = [fn for name, fn in selections.items()
                 if pattern == "them" or fnmatch.fnmatchcase(name, pattern)]
        if not found:
            raise UnsupportedRule(f"condition refers to unknown selection {pattern}")
        return found

    def atom():
        token = take()
        if token == "(":
            node = expr()
            if take() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            return node
        if token == "not":
            inner = atom()
            return lambda e: not inner(e)
        if token in {"1 of", "all of"}:
            group = names(take())
            if token == "1 of":
                return lambda e: any(fn(e) for fn in group)
            return lambda e: all(fn(e) for fn in group)
        if token not in selections:
            raise UnsupportedRule(f"condition refers to unknown selection {token}")
        return selections[token]

    def conjunction():
        node = atom()
        while peek() == "and":
            take()
            left, right = node, atom()
            node = lambda e, l=left, r=right: l(e) and r(e)  # noqa: E731
        return node

    def expr():
        node = conjunction()
        while peek() == "or":
            take()
            left, right = node, conjunction()
            node = lambda e, l=left, r=right: l(e) or r(e)  # noqa: E731
        return node

    result = expr()
    if position != len(tokens):
        raise UnsupportedRule("could not read the whole condition")
    return result


# ------------------------------------------------------------------ rules --

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    source: str
    product: str | None
    category: str | None
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    matcher: Callable[[NormalizedEvent], bool] = lambda e: False

    def applies_to(self, event: NormalizedEvent) -> bool:
        if self.product and self.product not in event_products(event):
            return False
        if self.category and self.category not in logsource_categories(event):
            return False
        return True

    def matches(self, event: NormalizedEvent) -> bool:
        return self.applies_to(event) and self.matcher(event)


def parse_rule(document: dict[str, Any], source: str) -> SigmaRule:
    if not isinstance(document, dict) or "detection" not in document:
        raise UnsupportedRule("not a detection rule")
    if "correlation" in document:
        raise UnsupportedRule("correlation rule")
    detection = dict(document["detection"])
    condition = detection.pop("condition", None)
    if isinstance(condition, list):
        if len(condition) != 1:
            raise UnsupportedRule("several conditions")
        condition = condition[0]
    if not condition:
        raise UnsupportedRule("no condition")
    detection.pop("timeframe", None)
    selections = {name: _selection(spec) for name, spec in detection.items()}
    matcher = _compile_condition(str(condition), selections)

    logsource = document.get("logsource") or {}
    category = logsource.get("category") or logsource.get("service")
    if category == "security":
        category = "authentication"
    tags = [str(t).lower() for t in document.get("tags") or []]
    techniques = sorted({t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    tactics = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgs]\d+.*", t)]
    level = str(document.get("level") or "medium").lower()
    return SigmaRule(
        id=str(document.get("id") or source),
        title=str(document.get("title") or Path(source).stem),
        level=level if level in LEVELS else "medium",
        description=str(document.get("description") or "").strip(),
        source=source,
        product=(logsource.get("product") or None),
        category=category,
        techniques=techniques,
        tactics=tactics,
        falsepositives=[str(f) for f in document.get("falsepositives") or []],
        matcher=matcher,
    )


@dataclass
class RuleSet:
    rules: list[SigmaRule] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def by_id(self) -> dict[str, SigmaRule]:
        return {r.id: r for r in self.rules}


def load_rules(paths: list[Path]) -> RuleSet:
    """Load every .yml/.yaml rule under the given files or folders."""
    ruleset = RuleSet()
    seen: set[str] = set()
    for root in paths:
        root = Path(root)
        files = [root] if root.is_file() else sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))
        for path in files:
            try:
                documents = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
            except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
                ruleset.skipped.append({"file": str(path), "reason": f"unreadable: {exc}".splitlines()[0]})
                continue
            for document in documents:
                if isinstance(document, dict) and document.get("action") == "global":
                    ruleset.skipped.append({"file": str(path), "reason": "multi-document global rule"})
                    break
                try:
                    rule = parse_rule(document, str(path))
                except (UnsupportedRule, re.error, ValueError, TypeError) as exc:
                    ruleset.skipped.append({"file": str(path), "reason": str(exc) or type(exc).__name__})
                    continue
                if rule.id in seen:
                    continue
                seen.add(rule.id)
                ruleset.rules.append(rule)
    return ruleset
