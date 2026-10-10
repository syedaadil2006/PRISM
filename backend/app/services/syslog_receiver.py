"""Syslog receiver: live logs from Linux servers and network devices.

Listens on UDP and/or TCP (RFC 3164 and RFC 5424 framing, one message per
line on TCP) and turns the messages PRISM understands into events:

* sshd: accepted / failed / invalid-user logons  -> authentication events
* sudo: commands run as another user             -> process events (so the
  usual suspicious-command checks apply)

Other messages are counted and ignored. Off by default (PRISM_SYSLOG_ENABLED),
because it opens a network port, and it binds to localhost unless told
otherwise. Syslog has no authentication of its own: only enable it on a
trusted network.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from app.core.logging_config import get_logger

if TYPE_CHECKING:
    from app.services.soc_state import SocState

logger = get_logger(__name__)

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|\[.*?\](?:\[.*?\])*) ?(?P<msg>.*)$"
)
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SSH_FAIL = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.+)$")


def _when(text: str, rfc5424: bool) -> datetime:
    if rfc5424:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    # RFC 3164 has no year or zone: this machine's local time, this year
    # (or last year if that would put the message in the future).
    local = datetime.now().astimezone()
    parsed = datetime.strptime("{} {}".format(local.year, " ".join(text.split())), "%Y %b %d %H:%M:%S")
    parsed = parsed.replace(tzinfo=local.tzinfo)
    if parsed > local + timedelta(days=1):
        parsed = parsed.replace(year=local.year - 1)
    return parsed


def parse_syslog_line(line: str) -> dict[str, Any] | None:
    """One syslog line -> a record PRISM's parsers read, or None if not relevant."""
    line = line.strip()
    match = _RFC5424.match(line)
    rfc5424 = match is not None
    if match is None:
        match = _RFC3164.match(line)
    if match is None:
        return None
    try:
        when = _when(match.group("ts"), rfc5424).astimezone(timezone.utc)
    except ValueError:
        return None
    host = match.group("host").split(".")[0].upper()
    app = (match.group("app") if rfc5424 else match.group("tag")).lower()
    message = match.group("msg")
    stamp = when.isoformat().replace("+00:00", "Z")

    if app == "sshd":
        for pattern, outcome in ((_SSH_OK, "success"), (_SSH_FAIL, "failure"), (_SSH_INVALID, "failure")):
            found = pattern.search(message)
            if found:
                # ECS authentication shape: handled by the ECS adapter.
                return {
                    "@timestamp": stamp,
                    "event": {"category": ["authentication"], "outcome": outcome},
                    "user": {"name": found.group("user")},
                    "source": {"ip": found.group("ip")},
                    "host": {"name": host},
                    "process": {"name": "sshd"},
                    "syslog": {"message": line},
                }
        return None

    if app == "sudo":
        found = _SUDO.match(message)
        if found:
            command = found.group("cmd").strip()
            # Sysmon process-creation shape, so command-line indicators apply.
            return {
                "EventID": "1",
                "UtcTime": stamp,
                "Computer": host,
                "User": found.group("user"),
                "Image": command.split()[0],
                "CommandLine": command,
                "ParentImage": "sudo",
            }
    return None


class SyslogReceiver:
    """UDP and TCP listeners that batch parsed messages into the live feed."""

    def __init__(self, state: SocState) -> None:
        self.state = state
        self.settings = state.settings.syslog
        self.received = 0
        self.parsed = 0
        self._pending: dict[str, list[dict[str, Any]]] = {}
        self._servers: list[Any] = []
        self._flusher: asyncio.Task[None] | None = None

    def handle_line(self, line: str, peer: str) -> None:
        self.received += 1
        record = parse_syslog_line(line)
        if record is None:
            return
        self.parsed += 1
        host = (record.get("Computer") or record.get("host", {}).get("name") or peer or "syslog").lower()
        self._pending.setdefault("syslog-" + host, []).append(record)

    async def flush(self) -> None:
        pending, self._pending = self._pending, {}
        for stream, records in pending.items():
            await self.state.ingest_live(records, stream)

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                await self.flush()
            except Exception as exc:  # noqa: BLE001 - the receiver must keep running
                logger.warning("syslog flush failed", extra={"error": str(exc)})

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        receiver = self

        class _Udp(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                for line in data.decode("utf-8", errors="replace").splitlines():
                    if line.strip():
                        receiver.handle_line(line, addr[0])

        async def _tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = (writer.get_extra_info("peername") or ("", 0))[0]
            try:
                while line := await reader.readline():
                    text = line.decode("utf-8", errors="replace")
                    if text.strip():
                        receiver.handle_line(text, peer)
            finally:
                writer.close()

        if self.settings.udp:
            transport, _ = await loop.create_datagram_endpoint(_Udp, local_addr=(self.settings.host, self.settings.port))
            self._servers.append(transport)
        if self.settings.tcp:
            self._servers.append(await asyncio.start_server(_tcp, self.settings.host, self.settings.port))
        self._flusher = asyncio.create_task(self._flush_loop())
        logger.info("syslog receiver listening", extra={"host": self.settings.host, "port": self.settings.port})

    async def stop(self) -> None:
        if self._flusher is not None:
            self._flusher.cancel()
        for server in self._servers:
            server.close()
        self._servers.clear()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.enabled,
            "listening": bool(self._servers),
            "address": "{}:{}".format(self.settings.host, self.settings.port),
            "protocols": [p for p, on in (("udp", self.settings.udp), ("tcp", self.settings.tcp)) if on],
            "messages_received": self.received,
            "messages_understood": self.parsed,
        }
