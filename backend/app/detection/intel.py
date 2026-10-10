"""Threat intelligence: known-bad domains, IP addresses, file hashes and URLs.

Indicator files are read from folders on this computer (PRISM never fetches
feeds itself, in line with local-only mode). Drop files into
``backend/data/intel/`` - exported from MISP, OpenCTI, a vendor portal or a
CERT advisory - and PRISM matches every event against them.

Accepted formats:

* **STIX 2.1** JSON bundles: ``indicator`` objects with patterns such as
  ``[domain-name:value = 'evil.example']``, ``[ipv4-addr:value = '203.0.113.7']``,
  ``[file:hashes.'SHA-256' = '...']`` or ``[url:value = '...']``;
* **CSV** with a header containing ``type`` and ``value`` (optional
  ``description``), e.g. ``domain,evil.example,Phishing kit``;
* **plain text**, one indicator per line; the type is recognised from the value
  (``#`` starts a comment).

A domain indicator also matches its sub-domains.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.models.events import NormalizedEvent

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
STIX_PATTERN = re.compile(
    r"\[(domain-name|ipv4-addr|ipv6-addr|url|file):(value|hashes\.'?[A-Za-z0-9-]+'?)\s*=\s*'([^']+)'\]"
)
TYPE_ALIASES = {
    "domain": "domain", "domain-name": "domain", "hostname": "domain", "fqdn": "domain",
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-dst": "ip", "ip-src": "ip", "ipv4-addr": "ip", "ipv6-addr": "ip",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "hash": "hash", "file": "hash",
    "url": "url", "uri": "url",
}


@dataclass(frozen=True)
class Indicator:
    kind: str  # domain | ip | hash | url
    value: str
    description: str
    source: str


def classify(value: str) -> str | None:
    value = value.strip()
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    return None


def _normal(kind: str, value: str) -> str:
    value = value.strip()
    return value.lower().rstrip(".") if kind in {"domain", "hash", "url"} else value


@dataclass
class IntelSet:
    domains: dict[str, Indicator] = field(default_factory=dict)
    ips: dict[str, Indicator] = field(default_factory=dict)
    hashes: dict[str, Indicator] = field(default_factory=dict)
    urls: dict[str, Indicator] = field(default_factory=dict)
    files: list[dict[str, object]] = field(default_factory=list)

    def add(self, kind: str, value: str, description: str, source: str) -> bool:
        kind = TYPE_ALIASES.get(kind.lower(), kind.lower())
        if kind not in {"domain", "ip", "hash", "url"} or not value.strip():
            return False
        key = _normal(kind, value)
        table = {"domain": self.domains, "ip": self.ips, "hash": self.hashes, "url": self.urls}[kind]
        table.setdefault(key, Indicator(kind, key, description.strip(), source))
        return True

    @property
    def count(self) -> int:
        return len(self.domains) + len(self.ips) + len(self.hashes) + len(self.urls)

    def match(self, event: NormalizedEvent) -> list[Indicator]:
        """Every indicator this event touches."""
        if not self.count:
            return []
        hits: list[Indicator] = []
        if event.domain and self.domains:
            labels = event.domain.lower().rstrip(".").split(".")
            for i in range(len(labels) - 1):  # the domain itself and each parent domain
                found = self.domains.get(".".join(labels[i:]))
                if found:
                    hits.append(found)
                    break
        for ip in event.ips():
            if ip in self.ips:
                hits.append(self.ips[ip])
        if self.hashes:
            text = " ".join(str(event.raw.get(k, "")) for k in ("Hashes", "hashes", "sha256", "md5", "sha1"))
            for value in re.findall(r"[A-Fa-f0-9]{32,64}", text):
                if value.lower() in self.hashes:
                    hits.append(self.hashes[value.lower()])
        if self.urls and event.command_line:
            lowered = event.command_line.lower()
            hits.extend(ind for url, ind in self.urls.items() if url in lowered)
        return hits


def _load_stix(text: str, source: str, intel: IntelSet) -> int:
    added = 0
    bundle = json.loads(text)
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else bundle
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator" or obj.get("revoked"):
            continue
        description = obj.get("name") or obj.get("description") or "STIX indicator"
        for kind, prop, value in STIX_PATTERN.findall(str(obj.get("pattern", ""))):
            mapped = "hash" if kind == "file" and prop.startswith("hashes") else kind
            added += intel.add(mapped, value, description, source)
    return added


def _load_csv(text: str, source: str, intel: IntelSet) -> int:
    added = 0
    reader = csv.DictReader(io.StringIO(text))
    headers = {h.lower().strip(): h for h in reader.fieldnames or []}
    if "value" not in headers and "indicator" not in headers:
        raise ValueError("CSV needs a 'value' (or 'indicator') column")
    for row in reader:
        value = (row.get(headers.get("value") or headers["indicator"]) or "").strip()
        kind = (row.get(headers.get("type", ""), "") or "").strip() or (classify(value) or "")
        description = (row.get(headers.get("description", ""), "") or "").strip() or "indicator list"
        added += intel.add(kind, value, description, source)
    return added


def _load_text(text: str, source: str, intel: IntelSet) -> int:
    added = 0
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        kind = classify(value) if value else None
        if kind:
            added += intel.add(kind, value, "indicator list", source)
    return added


def load_intel(folders: list[Path]) -> IntelSet:
    intel = IntelSet()
    for folder in folders:
        folder = Path(folder)
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if path.suffix.lower() not in {".json", ".csv", ".txt"}:
                continue
            try:
                text = path.read_text(encoding="utf-8-sig")
                loader = {".json": _load_stix, ".csv": _load_csv}.get(path.suffix.lower(), _load_text)
                added = loader(text, path.name, intel)
                intel.files.append({"file": path.name, "indicators": added})
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                intel.files.append({"file": path.name, "indicators": 0, "error": str(exc).splitlines()[0]})
    return intel
