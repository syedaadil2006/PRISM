"""Local-only (edge) mode: data never leaves the computer PRISM runs on.

On by default (PRISM_LOCAL_ONLY=true). It is enforced in code, not left to
configuration being correct:

* requests from any other machine are refused (HTTP 403), even if the server
  was started listening on the network;
* alert forwarding only delivers to this computer (loopback addresses);
* the optional language model is not used (findings are never sent to an API);
* the syslog receiver only listens on this computer.

Only an operator who sets PRISM_LOCAL_ONLY=false can turn any of this off.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

#: "testclient" is the in-process test client's name; it is not an address a
#: network peer can present, because real clients are identified by their IP.
_LOCAL_NAMES = {"localhost", "testclient"}


def is_loopback(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def url_is_local(url: str) -> bool:
    return is_loopback(urlparse(url).hostname)


def target_is_local(host_port: str) -> bool:
    host, _, _ = host_port.rpartition(":")
    return is_loopback(host or host_port)


def in_networks(host: str | None, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not host or not networks:
        return False
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any(address in network for network in networks)


class LocalOnlyMiddleware(BaseHTTPMiddleware):
    """Refuses every request that does not come from this computer."""

    def __init__(self, app, local_networks: list[str] | None = None) -> None:  # noqa: ANN001
        super().__init__(app)
        self.networks = [ipaddress.ip_network(n, strict=False) for n in (local_networks or [])]

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        client = request.client.host if request.client else None
        if not is_loopback(client) and not in_networks(client, self.networks):
            return JSONResponse(
                status_code=403,
                content={"detail": "PRISM is in local-only mode: it only accepts requests from this computer."},
            )
        return await call_next(request)
