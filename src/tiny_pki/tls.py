"""Build ``ssl.SSLContext`` objects for mutual TLS from the PEM bytes tiny-pki returns.

Python's ``ssl`` module loads a certificate chain only from files, so the
certificate and key (and a CRL, which ``cadata`` silently ignores) are written
to a private temporary directory for the duration of the call and removed
before it returns or raises. This module is not imported by ``import tiny_pki``.
"""

from __future__ import annotations

import os
import re
import shutil
import ssl
import tempfile
from pathlib import Path
from typing import Literal, get_args

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tiny_pki._keys import load_private_key
from tiny_pki.errors import TinyPkiError

ClientCertMode = Literal["none", "optional", "required"]
CrlCheck = Literal["none", "leaf", "chain"]

_CLIENT_CERT_MODES: dict[str, ssl.VerifyMode] = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}
_CRL_FLAGS: dict[str, ssl.VerifyFlags] = {
    "none": ssl.VerifyFlags.VERIFY_DEFAULT,
    "leaf": ssl.VERIFY_CRL_CHECK_LEAF,
    "chain": ssl.VERIFY_CRL_CHECK_CHAIN,
}
_MAX_TLS_VERSIONS = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.MAXIMUM_SUPPORTED)
_CRL_BLOCK = re.compile(rb"-----BEGIN X509 CRL-----.+?-----END X509 CRL-----", re.DOTALL)
_SPKI = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo


def server_context(
    cert_pem: bytes,
    key_pem: bytes,
    ca_cert_pem: bytes,
    *,
    crl_pem: bytes | None = None,
    client_cert: ClientCertMode = "required",
    crl_check: CrlCheck | None = None,
    max_tls_version: ssl.TLSVersion | None = None,
) -> ssl.SSLContext:
    """Return a TLS server context that presents ``cert_pem`` and verifies clients against ``ca_cert_pem``.

    ``cert_pem`` may carry the leaf followed by intermediate CA certificates;
    ``ca_cert_pem`` holds the CA certificates trusted for client certificates
    (system CAs are never loaded). ``client_cert`` is ``"required"``,
    ``"optional"`` or ``"none"``. With ``crl_pem`` (one or more PEM CRLs, such
    as a store's ``public/crl.pem``) revoked client certificates are refused:
    ``crl_check`` defaults to ``"leaf"`` then, and ``"chain"`` also checks the
    intermediate CAs, which needs a CRL from every CA in the chain. The minimum
    version is TLS 1.2; ``max_tls_version`` caps it.

    Raises:
        TinyPkiError: If a PEM is malformed, the key is encrypted or does not
            match ``cert_pem``, ``crl_check`` asks for CRL checks without
            ``crl_pem``, or ``crl_pem`` is given without client certificates.
    """
    if client_cert not in _CLIENT_CERT_MODES:
        raise TinyPkiError(f"Expected client_cert in {get_args(ClientCertMode)}, got {client_cert!r}")
    if crl_check is not None and crl_check not in _CRL_FLAGS:
        raise TinyPkiError(f"Expected crl_check in {get_args(CrlCheck)}, got {crl_check!r}")
    if crl_pem is None and crl_check not in (None, "none"):
        raise TinyPkiError(f"Expected crl_pem with crl_check={crl_check!r}; there is no CRL to check against")
    if crl_pem is not None:
        if client_cert == "none":
            raise TinyPkiError("Expected client_cert 'optional' or 'required' with crl_pem; the CRL checks clients")
        if crl_check == "none":
            raise TinyPkiError("Expected crl_check 'leaf' or 'chain' with crl_pem, got 'none'")
        _require_crls(crl_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _configure(context, cert_pem, key_pem, ca_cert_pem, crl_pem=crl_pem, max_tls_version=max_tls_version)
    context.verify_mode = _CLIENT_CERT_MODES[client_cert]
    if crl_pem is not None:
        context.verify_flags |= _CRL_FLAGS[crl_check or "leaf"]
    return context


def client_context(
    cert_pem: bytes,
    key_pem: bytes,
    ca_cert_pem: bytes,
    *,
    server_hostname_check: bool = True,
    max_tls_version: ssl.TLSVersion | None = None,
) -> ssl.SSLContext:
    """Return a TLS client context that presents ``cert_pem`` and verifies the server against ``ca_cert_pem``.

    The server certificate is always verified against ``ca_cert_pem`` only
    (system CAs are never loaded). ``server_hostname_check=False`` skips
    matching its SANs against the ``server_hostname`` you connect with, for
    servers reached by an address their certificate does not name. The minimum
    version is TLS 1.2; ``max_tls_version`` caps it.

    Raises:
        TinyPkiError: If a PEM is malformed, or the key is encrypted or does not match ``cert_pem``.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _configure(context, cert_pem, key_pem, ca_cert_pem, crl_pem=None, max_tls_version=max_tls_version)
    context.check_hostname = server_hostname_check
    return context


def _configure(
    context: ssl.SSLContext,
    cert_pem: bytes,
    key_pem: bytes,
    ca_cert_pem: bytes,
    *,
    crl_pem: bytes | None,
    max_tls_version: ssl.TLSVersion | None,
) -> None:
    _require_matching_key(cert_pem, key_pem)
    ca_certs = _load_certificates(ca_cert_pem, "ca_cert_pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if max_tls_version is not None:
        if max_tls_version not in _MAX_TLS_VERSIONS:
            raise TinyPkiError(f"Expected max_tls_version TLSv1_2 or later, got {max_tls_version!r}")
        context.maximum_version = max_tls_version
    context.load_verify_locations(
        cadata="".join(cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for cert in ca_certs)
    )
    directory = Path(tempfile.mkdtemp(prefix="tiny-pki-tls-"))
    try:
        os.chmod(directory, 0o700)
        cert_path = _write_private(directory / "cert.pem", cert_pem)
        key_path = _write_private(directory / "key.pem", key_pem)
        try:
            context.load_cert_chain(cert_path, key_path)
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", None) or "rejected by OpenSSL"
            raise TinyPkiError(f"Expected a certificate chain and key OpenSSL accepts ({reason})") from None
        if crl_pem is not None:
            context.load_verify_locations(cafile=_write_private(directory / "crl.pem", crl_pem))
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _require_matching_key(cert_pem: bytes, key_pem: bytes) -> None:
    leaf = _load_certificates(cert_pem, "cert_pem")[0]
    try:
        key = load_private_key(key_pem)
    except ValueError as exc:
        if isinstance(exc, TinyPkiError):
            raise
        raise TinyPkiError("Expected an unencrypted RSA or ECDSA P-256 PEM private key in key_pem") from None
    if key.public_key().public_bytes(*_SPKI) != leaf.public_key().public_bytes(*_SPKI):
        raise TinyPkiError("Expected the private key to match the certificate's public key")


def _load_certificates(data: bytes, name: str) -> list[x509.Certificate]:
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        raise TinyPkiError(f"Expected one or more PEM certificates in {name}") from None
    return certs


def _require_crls(crl_pem: bytes) -> None:
    blocks = _CRL_BLOCK.findall(crl_pem)
    if not blocks:
        raise TinyPkiError("Expected one or more PEM CRLs (-----BEGIN X509 CRL-----) in crl_pem")
    for block in blocks:
        try:
            x509.load_pem_x509_crl(block)
        except ValueError:
            raise TinyPkiError("Expected every PEM block in crl_pem to be a valid CRL") from None


def _write_private(path: Path, data: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return str(path)
