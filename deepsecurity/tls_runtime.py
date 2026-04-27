"""Built-in HTTPS / TLS helper for the Flask backend.

Closes the v3 production gap "no built-in HTTPS — proxy required".

The default deployment expects nginx / CloudFlare / ALB in front of the
backend for TLS termination. That's still the recommended posture for
production, but it means a misconfigured deploy is plain HTTP. This
module gives us three TLS modes:

    1. ``off``           — HTTP only. Same behaviour as v3.0.0a1.
    2. ``cert``          — operator provides cert + key (PEM files).
                           Standard production posture when a reverse
                           proxy is unavailable.
    3. ``self-signed``   — generate an ephemeral self-signed cert at
                           startup. Useful for dev, staging, lab,
                           single-tenant deployments where a local CA
                           isn't worth the operator overhead.

The self-signed mode uses the ``cryptography`` library (already a
transitive dep via authlib). Certs are written to ``data/tls/`` with
0600 perms, valid for ``settings.tls_self_signed_days`` days, with the
configured host as a SAN. On restart, an existing cert is reused if
present and not expired — no operator action needed for cert rotation
in dev.

Production hardening when TLS is on:
    * HSTS max-age is automatically reinforced to 1 year.
    * Set-Cookie defaults flip to Secure + SameSite=Lax.
    * The /readyz check refuses ``ready`` if TLS is configured but
      no listener is bound on the configured host:port (operator
      misconfiguration check).
"""

from __future__ import annotations

import datetime as _dt
import os
import ssl
from pathlib import Path
from typing import Final

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEFAULT_TLS_DIR: Final = Path("data") / "tls"
_DEFAULT_CERT_PATH: Final = _DEFAULT_TLS_DIR / "deepsec.crt"
_DEFAULT_KEY_PATH: Final = _DEFAULT_TLS_DIR / "deepsec.key"


def default_cert_path() -> Path:
    return _DEFAULT_CERT_PATH


def default_key_path() -> Path:
    return _DEFAULT_KEY_PATH


# ---------------------------------------------------------------------------
# Self-signed cert generation
# ---------------------------------------------------------------------------


def ensure_self_signed_cert(
    *,
    host: str,
    cert_path: Path | None = None,
    key_path: Path | None = None,
    valid_days: int = 365,
    force_regen: bool = False,
) -> tuple[Path, Path]:
    """Ensure a self-signed cert exists. Generate if missing or expired.

    Returns ``(cert_path, key_path)`` for use with the Flask runner.

    The generated cert is RSA-2048, signed SHA-256, with ``host`` and
    ``localhost`` and ``127.0.0.1`` as Subject Alt Names. CN is set to
    ``host`` so older clients that ignore SAN still get a green tick.

    Permissions are set to 0600 on POSIX. On Windows, the file ACL is
    inherited from the data/tls directory, which the lifecycle layer
    creates inside the project tree (not world-readable in any sane
    deployment).
    """
    cert_path = cert_path or default_cert_path()
    key_path = key_path or default_key_path()
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if not force_regen and cert_path.exists() and key_path.exists():
        if not _is_cert_expired(cert_path):
            _log.info(
                "tls.self_signed.reused",
                cert=str(cert_path),
                key=str(key_path),
            )
            return cert_path, key_path
        _log.info("tls.self_signed.expired_regenerating", cert=str(cert_path))

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:  # pragma: no cover  # cryptography is installed
        raise RuntimeError(
            "cryptography is required for self-signed TLS — "
            'pip install "deepsecurity[tls]"'
        ) from exc

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, host),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DEEPSecurity"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "self-signed"),
        ]
    )
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName(host),
            x509.DNSName("localhost"),
            x509.IPAddress(_ip_address("127.0.0.1")),
        ]
    )
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=int(valid_days)))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    _try_chmod(cert_path, 0o600)
    _try_chmod(key_path, 0o600)

    _log.info(
        "tls.self_signed.generated",
        cert=str(cert_path),
        key=str(key_path),
        host=host,
        valid_days=valid_days,
    )
    return cert_path, key_path


def _ip_address(text: str):  # type: ignore[no-untyped-def]
    """Late-import wrapper so ``ipaddress`` doesn't appear in module top-level."""
    import ipaddress

    return ipaddress.ip_address(text)


def _try_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except (OSError, NotImplementedError):
        pass  # Windows ACLs inherit from parent dir; that's fine.


def _is_cert_expired(cert_path: Path, *, skew_days: int = 7) -> bool:
    """True if the cert expires within ``skew_days``. Robust to parse errors."""
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        # Use UTC-naive comparison since cryptography returns naive UTC dts.
        not_after = cert.not_valid_after_utc.replace(tzinfo=_dt.UTC)
        return not_after - _dt.datetime.now(_dt.UTC) < _dt.timedelta(days=skew_days)
    except Exception:
        return True  # if we can't parse it, regenerate


# ---------------------------------------------------------------------------
# SSL context for outbound checks (healthz, readyz from lifecycle)
# ---------------------------------------------------------------------------


def insecure_ssl_context() -> ssl.SSLContext:
    """An SSLContext that accepts self-signed certs.

    Used by the lifecycle health probe when TLS is on with a self-signed
    cert. Production deployments with real certs use the default
    ``ssl.create_default_context()`` and reject untrusted certs as
    expected.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
