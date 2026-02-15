from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from urllib import request
from urllib.error import URLError


CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
BGPVIEW_URL = "https://api.bgpview.io/ip/{ip}"


class InvalidIPError(ValueError):
    pass


class UpstreamLookupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ASNResult:
    ip: str
    asn: int
    bgp_prefix: str
    country_code: str
    registry: str
    allocated_date: str
    as_name: str
    source: str = "team-cymru-whois"


def _validate_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise InvalidIPError(f"Invalid IP: {ip}") from exc
    return str(parsed)


def _parse_verbose_line(ip: str, line: str) -> ASNResult:
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 7:
        raise UpstreamLookupError("Unexpected upstream response format")

    asn_text = parts[0].upper().replace("AS", "").strip()
    try:
        asn = int(asn_text)
    except ValueError as exc:
        raise UpstreamLookupError("Invalid ASN value from upstream") from exc

    return ASNResult(
        ip=ip,
        asn=asn,
        bgp_prefix=parts[2],
        country_code=parts[3],
        registry=parts[4],
        allocated_date=parts[5],
        as_name=parts[6],
    )


def _lookup_team_cymru(normalized_ip: str, timeout_sec: float) -> ASNResult:
    query = f" -v {normalized_ip}\n".encode("utf-8")

    try:
        with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=timeout_sec) as sock:
            sock.sendall(query)
            sock.shutdown(socket.SHUT_WR)

            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError as exc:
        raise UpstreamLookupError("Unable to reach upstream ASN service") from exc

    raw = b"".join(chunks).decode("utf-8", errors="replace")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 2:
        raise UpstreamLookupError("No ASN data returned from upstream")

    return _parse_verbose_line(normalized_ip, lines[-1])


def _lookup_bgpview(normalized_ip: str, timeout_sec: float) -> ASNResult:
    url = BGPVIEW_URL.format(ip=normalized_ip)
    try:
        with request.urlopen(url, timeout=timeout_sec) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise UpstreamLookupError("Unable to reach fallback ASN service") from exc

    data = payload.get("data", {})
    prefixes = data.get("prefixes", [])
    if not prefixes:
        raise UpstreamLookupError("No ASN data returned from fallback service")

    first = prefixes[0]
    asn_info = first.get("asn", {})
    try:
        asn = int(asn_info.get("asn"))
    except (TypeError, ValueError) as exc:
        raise UpstreamLookupError("Invalid ASN value from fallback service") from exc

    rir_alloc = data.get("rir_allocation", {})
    as_name = asn_info.get("description_short") or asn_info.get("name") or ""
    return ASNResult(
        ip=normalized_ip,
        asn=asn,
        bgp_prefix=first.get("prefix", ""),
        country_code=asn_info.get("country_code", ""),
        registry=str(rir_alloc.get("rir_name", "")).lower(),
        allocated_date=rir_alloc.get("date_allocated", ""),
        as_name=as_name,
        source="bgpview.io",
    )


def lookup_asn(ip: str, timeout_sec: float = 4.0) -> ASNResult:
    normalized_ip = _validate_ip(ip)

    try:
        return _lookup_team_cymru(normalized_ip, timeout_sec)
    except UpstreamLookupError:
        return _lookup_bgpview(normalized_ip, timeout_sec)
