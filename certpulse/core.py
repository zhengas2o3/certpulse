"""TLS probing logic (stdlib only)."""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import socket
import ssl
from dataclasses import asdict, dataclass, field


@dataclass
class CertResult:
    target: str
    host: str
    port: int
    ok: bool
    days_left: float | None = None
    not_after: str | None = None
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = field(default_factory=list)
    tls_version: str | None = None
    error: str | None = None
    verified: bool = True

    def status(self, warn_days: int, crit_days: int) -> str:
        if not self.ok:
            return "ERROR"
        if self.days_left is None:
            return "ERROR"
        if self.days_left < 0:
            return "EXPIRED"
        if self.days_left < crit_days:
            return "CRITICAL"
        if self.days_left < warn_days:
            return "WARNING"
        return "OK"

    def to_dict(self) -> dict:
        return asdict(self)


def parse_target(target: str, default_port: int = 443) -> tuple[str, int, str | None]:
    """Parse ``host``, ``host:port``, ``[v6]:port``, ``https://host/path`` or ``host:port@sni``.

    Returns (host, port, sni). ``sni`` is None when it equals the host.
    """
    t = target.strip()
    sni = None
    if "@" in t and "://" not in t:
        t, sni = t.rsplit("@", 1)
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    port = default_port
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif t.count(":") == 1:
        host, p = t.split(":")
        port = int(p)
    else:
        host = t
    if not host:
        raise ValueError(f"empty host in {target!r}")
    if not 0 < port < 65536:
        raise ValueError(f"bad port in {target!r}")
    return host, port, sni


def _name(rdn_seq) -> str:
    parts = {}
    for rdn in rdn_seq or ():
        for key, value in rdn:
            parts[key] = value
    return parts.get("commonName") or parts.get("organizationName") or ""


def parse_not_after(value: str) -> dt.datetime:
    return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=dt.timezone.utc)


def _fetch(host: str, port: int, sni: str, timeout: float, verify: bool) -> tuple[dict, str | None]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            cert = tls.getpeercert()
            version = tls.version()
            if not cert:  # CERT_NONE returns {} - decode the DER ourselves
                der = tls.getpeercert(binary_form=True)
                cert = _decode_der(der)
            return cert, version


def _decode_der(der: bytes) -> dict:
    """Decode a DER cert into the getpeercert() dict shape via a temp PEM file."""
    import os
    import tempfile

    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        os.unlink(path)


def check_host(target: str, timeout: float = 8.0, now: dt.datetime | None = None) -> CertResult:
    try:
        host, port, sni = parse_target(target)
    except ValueError as exc:
        return CertResult(target, target, 0, ok=False, error=str(exc))
    server_name = sni or host
    verified = True
    try:
        try:
            cert, version = _fetch(host, port, server_name, timeout, verify=True)
        except ssl.SSLCertVerificationError as exc:
            # still report expiry for broken chains / expired certs
            verified = False
            cert, version = _fetch(host, port, server_name, timeout, verify=False)
            verify_error = exc.verify_message or str(exc)
        else:
            verify_error = None
    except (OSError, ssl.SSLError, ValueError) as exc:
        return CertResult(target, host, port, ok=False, error=f"{type(exc).__name__}: {exc}")

    not_after = parse_not_after(cert["notAfter"])
    now = now or dt.datetime.now(dt.timezone.utc)
    days_left = (not_after - now).total_seconds() / 86400
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return CertResult(
        target=target, host=host, port=port, ok=True,
        days_left=round(days_left, 2), not_after=not_after.isoformat(),
        issuer=_name(cert.get("issuer")), subject=_name(cert.get("subject")),
        sans=sans, tls_version=version, verified=verified,
        error=f"verification failed: {verify_error}" if verify_error else None,
    )


def check_many(targets: list[str], timeout: float = 8.0, workers: int = 16) -> list[CertResult]:
    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets) or 1))) as pool:
        return list(pool.map(lambda t: check_host(t, timeout), targets))
