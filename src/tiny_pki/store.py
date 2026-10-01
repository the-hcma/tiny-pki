"""Filesystem store for CLI-managed certificate authorities.

Writes require an explicit store directory (``--store`` / ``TINY_PKI_STORE``).
Private keys, bundles, and ``index.json`` are written with mode ``0o600``;
directories the store creates are ``0o700``, except the key-free ``public/``
(``0o755``), which mirrors ``ca.crt`` and ``crl.pem`` for TLS servers. Leaf and
bundle writes refuse a symlink at any path component, and index paths must point
at a certificate file under ``clients/``, ``servers/`` or ``intermediates/``.

Layout (one CA per store root)::

    $STORE/
      ca/ca.crt  ca/ca.key  ca/crl.pem  ca/crlnumber  ca/crldays  ca/index.json
      ca/ocspdays  ca/ocspurl           (only once OCSP stapling / an OCSP URL is set up)
      ca/chain.pem  ca/chain-crl.pem    (only when the CA is an intermediate)
      public/ca.crt  public/crl.pem  public/ca-chain.pem  public/ocsp/{cn}.der
      clients/{cn}-{serial}.{crt,key}   (no .key for a certificate signed from a CSR)
      servers/{cn}-{serial}.{crt,key}   (likewise)
      intermediates/{cn}-{serial}.crt   (intermediate CAs this CA signed; never a key)
      bundles/{cn}-{serial}.p12

A store whose CA is an intermediate keeps the certificates above it in
``ca/chain.pem`` (issuer first, root last) and their CRLs in ``ca/chain-crl.pem``
(see :meth:`CertificateStore.import_chain_crl`). ``public/crl.pem`` then holds
its own CRL followed by those, because a TLS server that checks CRLs (nginx
``ssl_crl``) checks every CA in the chain; ``ca/crl.pem`` stays its own only.

Legacy flat layouts (``ca.crt`` / ``certs/`` at the store root) are migrated
automatically on first ``ensure_layout``.

Methods that change the index (``add_certificate``, ``mark_revoked``,
``delete_certificate`` and the CLI-shaped ``issue_client`` / ``issue_server`` /
``sign_client_csr`` / ``sign_server_csr`` / ``issue_intermediate`` /
``sign_intermediate_csr`` / ``revoke`` / ``delete``) republish
``ca/crl.pem`` with the store's CA key, so the CRL never lags ``index.json``; once
:meth:`CertificateStore.publish_ocsp` has run, every CRL publish also refreshes
the stapled OCSP responses in ``public/ocsp/``.
:func:`check_store` is the store health check behind ``tiny-pki check``.

Every method that modifies the store holds an exclusive ``fcntl.flock`` on
``ca/.lock`` (see :meth:`CertificateStore.lock`), so concurrent processes cannot
lose an index update or publish a CRL from a stale revoked set. Reads take no lock,
except the first read of a legacy layout, which migrates it (a write).
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import stat
import sys
import threading
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Concatenate, Literal, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509.oid import NameOID

from tiny_pki._fsutil import write_file_atomic
from tiny_pki._keys import load_ca_private_key
from tiny_pki.check import CertificateStatus, Status, check_certificate, check_crl
from tiny_pki.constants import (
    DEFAULT_CLIENT_VALIDITY_DAYS,
    DEFAULT_CRL_VALIDITY_DAYS,
    DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
    DEFAULT_KEY_TYPE,
    DEFAULT_OCSP_VALIDITY_DAYS,
    DEFAULT_SERVER_VALIDITY_DAYS,
    MAX_OCSP_VALIDITY_DAYS,
    MAX_STORE_CRL_VALIDITY_DAYS,
    KeyType,
)
from tiny_pki.errors import TinyPkiError
from tiny_pki.inspect import (
    get_certificate_expiry,
    get_certificate_fingerprint,
    get_certificate_serial_number,
    get_certificate_uris,
)
from tiny_pki.issue import (
    generate_client_certificate,
    generate_intermediate_ca_certificate,
    generate_server_certificate,
    require_name_constraints_within,
    sign_client_csr,
    sign_intermediate_csr,
    sign_server_csr,
)
from tiny_pki.names import normalize_http_url
from tiny_pki.ocsp import ForeignCertificateError, generate_ocsp_response, generate_ocsp_response_for_certificate
from tiny_pki.revoke import generate_crl
from tiny_pki.secrets import (
    decrypt_private_key_scrypt,
    encrypt_private_key_scrypt,
    require_strong_secret,
)

if sys.platform != "win32":
    import fcntl

CertKind = Literal["client", "intermediate", "server"]
CertStatus = Literal["active", "all", "revoked"]
CheckKind = Literal["ca", "client", "crl", "server"]
CHECK_KINDS: frozenset[CheckKind] = frozenset({"ca", "client", "crl", "server"})


@dataclass(frozen=True)
class IssuedCertificate:
    """One certificate recorded in the store index."""

    common_name: str
    kind: CertKind
    serial_number: str
    cert_path: str
    key_path: str
    not_valid_after: str
    fingerprint: str
    revoked_at: str | None = None
    uri_san: str | None = None


def _locked[**P, R](
    method: Callable[Concatenate[CertificateStore, P], R],
) -> Callable[Concatenate[CertificateStore, P], R]:
    @functools.wraps(method)
    def wrapper(self: CertificateStore, *args: P.args, **kwargs: P.kwargs) -> R:
        with self.lock():
            return method(self, *args, **kwargs)

    return wrapper


class CertificateStore:
    """On-disk CA material + issued-certificate index."""

    def __init__(self, root: Path | str) -> None:
        text = str(root).strip()
        if not text or text == ".":
            raise ValueError("Expected a non-empty store path")
        self.root = Path(text).expanduser().resolve()

    @property
    def bundles_dir(self) -> Path:
        return self.root / "bundles"

    @property
    def ca_cert_path(self) -> Path:
        return self.root / "ca" / "ca.crt"

    @property
    def ca_chain_path(self) -> Path:
        """Certificates above an intermediate CA (issuer first, root last); absent for a root CA."""
        return self.root / "ca" / "chain.pem"

    @property
    def ca_dir(self) -> Path:
        return self.root / "ca"

    @property
    def ca_key_path(self) -> Path:
        return self.root / "ca" / "ca.key"

    @property
    def clients_dir(self) -> Path:
        return self.root / "clients"

    @property
    def chain_crl_path(self) -> Path:
        """CRLs of the CAs in :attr:`ca_chain_path`, imported with :meth:`import_chain_crl`."""
        return self.root / "ca" / "chain-crl.pem"

    @property
    def crl_path(self) -> Path:
        return self.root / "ca" / "crl.pem"

    @property
    def crl_validity_days(self) -> int:
        """Lifetime (days to ``nextUpdate``) of every CRL this store publishes; 30 until set."""
        path = self._validated_write_path("ca/crldays")
        if not path.is_file():
            return DEFAULT_CRL_VALIDITY_DAYS
        text = path.read_text(encoding="utf-8").strip()
        if not text.isdigit():
            raise ValueError(f"Expected a decimal number of days in {path}")
        return _require_crl_validity_days(int(text))

    @property
    def index_path(self) -> Path:
        return self.root / "ca" / "index.json"

    @property
    def intermediates_dir(self) -> Path:
        return self.root / "intermediates"

    @property
    def lock_path(self) -> Path:
        return self.root / "ca" / ".lock"

    @property
    def ocsp_dir(self) -> Path:
        """Key-free directory of pre-signed OCSP responses for stapling (``public/ocsp``)."""
        return self.root / "public" / "ocsp"

    @property
    def ocsp_url(self) -> str | None:
        """OCSP responder URL written into newly issued leaves (Authority Information Access); ``None`` until set."""
        path = self._validated_write_path("ca/ocspurl")
        if not path.is_file():
            return None
        return normalize_http_url(path.read_text(encoding="utf-8"), f"the OCSP URL in {path}")

    @property
    def ocsp_validity_days(self) -> int | None:
        """Lifetime of the pre-signed OCSP responses, or ``None`` while the store does not publish them."""
        path = self._validated_write_path("ca/ocspdays")
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8").strip()
        if not text.isdigit():
            raise ValueError(f"Expected a decimal number of days in {path}")
        return _require_ocsp_validity_days(int(text))

    @property
    def public_dir(self) -> Path:
        """Key-free directory holding ``ca.crt`` and ``crl.pem`` for relying parties."""
        return self.root / "public"

    @property
    def servers_dir(self) -> Path:
        return self.root / "servers"

    @_locked
    def add_certificate(
        self,
        *,
        common_name: str,
        kind: CertKind,
        serial_number: int,
        cert_pem: bytes,
        key_pem: bytes | None,
        not_valid_after: datetime,
        fingerprint: str,
        keep_previous: bool = False,
        key_secret: str | None = None,
        uri_san: str | None = None,
    ) -> IssuedCertificate:
        """Write cert/key PEMs and append an index entry.

        ``key_pem=None`` records a certificate whose private key never reached the
        store (issued from a CSR): no key file is written and ``key_path`` is empty.

        Revoked tombstones for the same common name are retained for CRL generation.
        Re-issuing under an existing live CN auto-revokes the superseded serial, and
        ``ca/crl.pem`` is republished (when the store has a CA) so it lists it.
        ``keep_previous=True`` leaves earlier live certificates of the same kind
        for the CN live (routine rotation); the CN then resolves to the new one,
        and the older serials are :meth:`superseded_serials` until revoked by
        serial. A live certificate of the other leaf kind is still revoked. Encrypted
        stores require ``key_secret`` so the CRL can be republished.

        ``kind="intermediate"`` records an intermediate CA this CA signed: it takes
        no key (the key belongs in the intermediate's own store), a renewal never
        revokes the previous certificate (its leaves still chain to it; revoke it
        by serial once they are replaced), and its CN cannot be shared with a leaf.

        ``uri_san`` is recorded as the entry's URI SAN; it is not read from ``cert_pem``.
        """
        self.ensure_layout()
        if kind not in _CERT_DIRS:
            raise ValueError(f"Expected kind 'client', 'intermediate' or 'server', got {kind!r}")
        if kind == "intermediate" and key_pem is not None:
            raise ValueError("Expected no key for an intermediate CA; its key belongs in its own store")
        self._require_ca_signing_key(key_secret)
        common_name = common_name.strip()
        if not common_name:
            raise ValueError("Expected a non-empty common_name")
        serial_hex = format(serial_number, "x")
        for existing in self._read_index():
            if existing.serial_number == serial_hex and existing.revoked_at is not None:
                raise ValueError(f"Serial {serial_hex} is already revoked; refuse to re-issue under that serial")
            if (
                existing.common_name.casefold() == common_name.casefold()
                and existing.revoked_at is None
                and existing.cert_path
                and existing.serial_number != serial_hex
                and (existing.kind == "intermediate") != (kind == "intermediate")
            ):
                raise ValueError(
                    f"Expected {common_name!r} to name either an intermediate CA or a leaf, but a live "
                    f"{existing.kind} certificate (serial 0x{existing.serial_number}) already uses it; pick another CN"
                )
        leaf_dir = _CERT_DIRS[kind]
        if kind == "intermediate":
            keep_previous = True
            _make_private_dir(self._validated_write_path(leaf_dir))
        safe = _safe_filename(common_name)
        cert_rel = f"{leaf_dir}/{safe}-{serial_hex}.crt"
        key_rel = f"{leaf_dir}/{safe}-{serial_hex}.key" if key_pem is not None else ""
        _write_plain(self._validated_write_path(cert_rel), cert_pem)
        if key_pem is not None:
            _write_secret(self._validated_write_path(key_rel), key_pem)

        entry = IssuedCertificate(
            common_name=common_name,
            kind=kind,
            serial_number=serial_hex,
            cert_path=cert_rel,
            key_path=key_rel,
            not_valid_after=not_valid_after.astimezone(UTC).isoformat(),
            fingerprint=fingerprint,
            uri_san=uri_san,
        )
        # Replace a prior live entry for the same CN: revoke it (tombstone for CRL)
        # and unlink its on-disk material after the index is committed. Same serial
        # is an idempotent rewrite.
        when = datetime.now(UTC).isoformat()
        entries: list[IssuedCertificate] = []
        unlink_paths: list[str] = []
        for existing in self._read_index():
            if (
                existing.common_name.casefold() == common_name.casefold()
                and existing.revoked_at is None
                and existing.cert_path
            ):
                if existing.serial_number == serial_hex:
                    continue
                if keep_previous and existing.kind == kind:
                    entries.append(existing)
                    continue
                if existing.cert_path:
                    unlink_paths.append(existing.cert_path)
                if existing.key_path:
                    unlink_paths.append(existing.key_path)
                entries.append(replace(existing, cert_path="", key_path="", revoked_at=when))
            else:
                entries.append(existing)
        entries.append(entry)
        self._write_index(entries)
        for rel in unlink_paths:
            (self.root / rel).unlink(missing_ok=True)
        self._republish_crl(entry, key_secret=key_secret)
        return entry

    @_locked
    def delete_certificate(
        self, identity: str, *, force: bool = False, key_secret: str | None = None
    ) -> IssuedCertificate:
        """Remove cert/key files from disk, keeping a revoked tombstone in the index.

        Active (non-revoked) certificates require ``force=True``, which revokes
        them now before deleting. The tombstone keeps the serial, and ``ca/crl.pem``
        is republished (when the store has a CA) so it still lists it.

        The index is rewritten before unlinking files so a mid-delete failure
        cannot leave the index pointing at missing paths. A common name shared
        by two live certificates is refused; pass the serial instead.
        """
        entry = self.get_certificate(identity, require_unique=True)
        if entry is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        if entry.revoked_at is None and not force:
            raise ValueError(
                f"Certificate {entry.common_name!r} is still active; revoke it first, "
                "or pass force=True (CLI: --force) to revoke and delete it in one step"
            )
        self._require_ca_signing_key(key_secret)

        tombstone = replace(
            entry, cert_path="", key_path="", revoked_at=entry.revoked_at or datetime.now(UTC).isoformat()
        )
        remaining = [
            tombstone if (e.common_name == entry.common_name and e.serial_number == entry.serial_number) else e
            for e in self._read_index()
        ]
        self._write_index(remaining)
        if entry.cert_path:
            (self.root / entry.cert_path).unlink(missing_ok=True)
        if entry.key_path:
            (self.root / entry.key_path).unlink(missing_ok=True)
        self._republish_crl(entry, key_secret=key_secret)
        return tombstone

    def delete(self, identity: str, *, force: bool = False, key_secret: str | None = None) -> IssuedCertificate:
        """Delete a certificate's files, as ``tiny-pki delete``; see :meth:`delete_certificate`."""
        return self.delete_certificate(identity, force=force, key_secret=key_secret)

    @_locked
    def ensure_layout(self) -> None:
        """Create the store directory tree (does not write a CA).

        Migrates a legacy flat layout (``ca.crt`` / ``certs/`` at the root) when
        present.
        """
        self.root.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        if self._is_legacy_layout():
            self._migrate_legacy_layout()
        self._make_subdirs()
        for directory in (self.root, self.ca_dir, self.clients_dir, self.servers_dir, self.bundles_dir):
            _drop_world_write(directory)
        self._sync_public_dir()
        if not self.index_path.exists():
            if self.ca_cert_path.is_file() and self.ca_key_path.is_file():
                raise FileNotFoundError(f"Expected index.json under {self.ca_dir} (CA present but index missing)")
            self._write_index([])

    def get_certificate(self, identity: str, *, require_unique: bool = False) -> IssuedCertificate | None:
        """Lookup by common name or hex serial (case-insensitive; ``0x`` optional).

        A needle that is one certificate's serial (with or without ``0x``) and a
        different certificate's common name is refused as ambiguous, so a CN
        crafted to look like a serial cannot redirect the lookup. When several
        entries match a common name, the newest live (non-revoked) entry wins, so
        re-issue (including ``keep_previous`` rotation) resolves to the current
        certificate. With ``require_unique=True`` a common name shared by two live
        certificates raises ``ValueError`` instead, as revoke and delete need.
        """
        needle = identity.strip()
        if not needle:
            return None
        wanted_serial = needle.lower().removeprefix("0x")
        by_serial: list[IssuedCertificate] = []
        by_name: list[IssuedCertificate] = []
        for entry in self._read_index():
            if not entry.cert_path:
                continue
            if entry.serial_number.lower() == wanted_serial:
                by_serial.append(entry)
            elif entry.common_name.casefold() == needle.casefold():
                by_name.append(entry)
        if by_serial and by_name:
            raise ValueError(
                f"Expected {needle!r} to identify one certificate, but it is the serial of "
                f"{by_serial[0].common_name!r} and the common name of the certificate with serial "
                f"{by_name[0].serial_number}; use {by_serial[0].common_name!r} or 0x{by_name[0].serial_number}"
            )
        candidates = by_serial or by_name
        if not candidates:
            return None
        live = [entry for entry in candidates if entry.revoked_at is None]
        if require_unique and not by_serial and len(live) > 1:
            serials = ", ".join(f"0x{entry.serial_number}" for entry in live)
            raise ValueError(
                f"Expected {needle!r} to identify one certificate, but {len(live)} live certificates share "
                f"that common name ({serials}); pass the serial of the one you mean"
            )
        if live:
            return live[-1]
        return candidates[0]

    def has_ca(self) -> bool:
        self._maybe_migrate_legacy_layout()
        return self.ca_cert_path.is_file() and self.ca_key_path.is_file()

    @property
    def ca_key_encrypted(self) -> bool:
        """Whether the stored CA key uses tiny-pki's versioned Fernet format."""
        self._maybe_migrate_legacy_layout()
        if not self.ca_key_path.is_file():
            return False
        ca_key = self.ca_key_path.read_bytes()
        return ca_key.startswith(_ENCRYPTED_CA_KEY_PREFIX)

    @contextmanager
    def lock(self) -> Generator[None]:
        """Hold the store's exclusive write lock (``flock`` on ``ca/.lock``) until the block exits.

        Every method that modifies the store takes it, so hold it yourself only to
        make a read-then-write sequence atomic, such as reading
        :meth:`revoked_entries` and :meth:`next_crl_number` before :meth:`write_crl`.
        Re-entrant within a thread; blocks while another process or thread holds it.

        Raises:
            TinyPkiError: ``fcntl.flock`` is unavailable (Windows); the store is
                never modified without the lock.
        """
        if sys.platform == "win32":
            raise TinyPkiError(
                f"Expected fcntl.flock to lock the store at {self.root}; refusing to modify it without a lock"
            )
        depth: dict[Path, int] = _HELD_LOCKS.__dict__.setdefault("depth", {})
        key = self.lock_path
        if depth.get(key):
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        self.root.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        self.ca_dir.mkdir(mode=_DIR_MODE, exist_ok=True)
        path = self._validated_write_path("ca/.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            depth[key] = 1
            materials: dict[Path, tuple[bytes, bytes]] = _HELD_LOCKS.__dict__.setdefault("ca_material", {})
            materials.pop(key, None)
            try:
                yield
            finally:
                del depth[key]
                materials.pop(key, None)
        finally:
            os.close(fd)

    def list_certificates(
        self,
        *,
        kind: CertKind | None = None,
        status: CertStatus = "all",
    ) -> list[IssuedCertificate]:
        """Return index entries filtered by kind and/or status.

        ``status="all"`` returns every entry that still has on-disk paths (live or
        revoked). ``status="revoked"`` includes tombstones (empty paths) so CRL
        history remains visible.
        """
        if status not in ("active", "all", "revoked"):
            raise ValueError(f"Expected status 'active', 'all', or 'revoked', got {status!r}")
        result: list[IssuedCertificate] = []
        for entry in self._read_index():
            if kind is not None and entry.kind != kind:
                continue
            if status == "active":
                if entry.revoked_at is not None or not entry.cert_path:
                    continue
            elif status == "revoked":
                if entry.revoked_at is None:
                    continue
            elif not entry.cert_path:
                continue
            result.append(entry)
        return result

    @_locked
    def mark_revoked(
        self, identity: str, *, revoked_at: datetime | None = None, key_secret: str | None = None
    ) -> IssuedCertificate:
        """Mark an issued cert revoked in the index.

        Idempotent: an already-revoked entry keeps its original ``revoked_at``.
        Identity resolution matches :meth:`get_certificate` (strip / ``0x`` serial).
        ``ca/crl.pem`` is republished (when the store has a CA) so it lists the serial.
        A common name shared by two live certificates is refused; pass the serial instead.
        """
        target = self.get_certificate(identity, require_unique=True)
        if target is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        self._require_ca_signing_key(key_secret)
        when = (revoked_at or datetime.now(UTC)).astimezone(UTC)
        entries = self._read_index()
        updated: list[IssuedCertificate] = []
        found: IssuedCertificate | None = None
        for entry in entries:
            if entry.common_name == target.common_name and entry.serial_number == target.serial_number:
                if entry.revoked_at is not None:
                    found = entry
                    updated.append(entry)
                else:
                    found = replace(entry, revoked_at=when.isoformat())
                    updated.append(found)
            else:
                updated.append(entry)
        if found is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        self._write_index(updated)
        self._republish_crl(found, key_secret=key_secret)
        return found

    @_locked
    def publish_crl(self, *, validity_days: int | None = None, key_secret: str | None = None) -> bytes:
        """Sign the index's revoked set with the store's CA key and publish it as ``ca/crl.pem``.

        The revoked set, the CRL number and the write happen under one lock, so a
        concurrent revoke is never dropped from the newest CRL. ``validity_days``
        signs for that many days and, once the CRL is written, becomes the stored
        lifetime (see :meth:`set_crl_validity_days`); otherwise
        :attr:`crl_validity_days` is used. A failed publish leaves it unchanged.
        When OCSP stapling is on (see :meth:`publish_ocsp`), every response in
        ``public/ocsp/`` is refreshed under the same lock.

        Returns:
            The published CRL in PEM format.
        """
        crl, ca_cert, ca_key = self._sign_and_write_crl(validity_days, key_secret)
        ocsp_days = self.ocsp_validity_days
        if ocsp_days is not None:
            self._write_ocsp_responses(ca_cert, ca_key, ocsp_days)
        return crl

    @_locked
    def publish_ocsp(self, *, validity_days: int | None = None, key_secret: str | None = None) -> list[Path]:
        """Pre-sign an OCSP response for every server certificate under ``public/ocsp/``, for stapling.

        Each server certificate still on disk gets ``public/ocsp/<cn>.der`` (the
        name stays the same when the certificate is renewed; two CNs that map to
        the same file name get ``<cn>-<serial>.der`` instead). A revoked one gets
        a ``revoked`` response, so a server still presenting it staples its
        revocation; responses for deleted or replaced certificates are removed.
        The bare ``<cn>.der`` belongs to the newest live certificate of that CN,
        or to the newest one once none is live. The first call turns publishing on:
        from then on issuing, revoking or deleting a server certificate refreshes
        the responses of its CN, and every :meth:`publish_crl` (the ``crl``
        command) refreshes all of them, so run the CRL timer well inside their lifetime.
        ``validity_days`` (1..``MAX_OCSP_VALIDITY_DAYS``) becomes the stored
        lifetime; otherwise the stored one, or ``DEFAULT_OCSP_VALIDITY_DAYS``, is used.

        Returns:
            The response files written.
        """
        stored = self.ocsp_validity_days
        if validity_days is not None:
            days = _require_ocsp_validity_days(validity_days)
        else:
            days = stored if stored is not None else DEFAULT_OCSP_VALIDITY_DAYS
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        written = self._write_ocsp_responses(*ca_material, days)
        _write_plain(self._validated_write_path("ca/ocspdays"), f"{days}\n".encode())
        return written

    @_locked
    def disable_ocsp(self) -> None:
        """Stop publishing OCSP responses: remove the responses, ``public/ocsp/`` and the stored lifetime.

        Files other than ``*.der`` in ``public/ocsp/`` are left alone, and so is
        the directory while it still holds any.
        """
        directory = self._validated_write_path("public/ocsp")
        if directory.is_dir():
            for path in directory.iterdir():
                if path.suffix == ".der":
                    path.unlink()
            if not any(directory.iterdir()):
                directory.rmdir()
        self._validated_write_path("ca/ocspdays").unlink(missing_ok=True)

    @_locked
    def set_ocsp_url(self, url: str | None) -> None:
        """Persist the OCSP responder URL written into every later leaf, or clear it with ``None``.

        Certificates already issued keep whatever they were issued with.

        Raises:
            TinyPkiError: ``url`` is not an ``http://`` or ``https://`` URL with a host.
        """
        path = self._validated_write_path("ca/ocspurl")
        if url is None:
            path.unlink(missing_ok=True)
            return
        text = normalize_http_url(url, "the OCSP URL")
        self.ca_dir.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        _write_plain(path, f"{text}\n".encode())

    @_locked
    def respond_ocsp(self, request_der: bytes, *, key_secret: str | None = None) -> bytes:
        """Answer a DER OCSP request from the index, for a consumer's own responder.

        Serials in ``index.json`` are ``good`` or ``revoked`` (tombstones
        included); any other serial is ``unknown``. The answer comes from one
        snapshot of the index taken under the store lock, so it never mixes the
        state before and after a concurrent revoke or issue. The lifetime is
        :attr:`ocsp_validity_days`, or ``DEFAULT_OCSP_VALIDITY_DAYS`` while
        stapling is off. See :func:`tiny_pki.generate_ocsp_response`.

        Each call takes the store lock (so it waits for, and holds up, issuing and
        revoking) and, for an encrypted CA, decrypts the key with the deliberately
        slow Scrypt. A responder with real traffic should serve the pre-signed
        ``public/ocsp/`` files, or read the CA once with :meth:`read_ca` and call
        :func:`tiny_pki.generate_ocsp_response` with an index snapshot it refreshes.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        entries = self._read_index()
        return generate_ocsp_response(
            *ca_material,
            request_der,
            issued_serials={int(entry.serial_number, 16) for entry in entries},
            revoked_entries=[
                (int(entry.serial_number, 16), datetime.fromisoformat(entry.revoked_at))
                for entry in entries
                if entry.revoked_at is not None
            ],
            validity_days=self.ocsp_validity_days or DEFAULT_OCSP_VALIDITY_DAYS,
        )

    @_locked
    def set_crl_validity_days(self, days: int) -> None:
        """Persist the CRL lifetime used by every later publish, including implicit ones.

        Raises:
            TinyPkiError: ``days`` is outside 1..``MAX_STORE_CRL_VALIDITY_DAYS`` (365).
        """
        _require_crl_validity_days(days)
        self.ca_dir.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        _write_plain(self._validated_write_path("ca/crldays"), f"{days}\n".encode())

    @_locked
    def issue_client(
        self,
        common_name: str,
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
        key_size: int | None = None,
        key_type: KeyType = DEFAULT_KEY_TYPE,
        allow_long_validity: bool = False,
        allow_dn_special_chars: bool = False,
        keep_previous: bool = False,
        key_secret: str | None = None,
        uri_san: str | None = None,
    ) -> IssuedCertificate:
        """Issue and record a client certificate, as ``tiny-pki create client``.

        Arguments match :func:`tiny_pki.generate_client_certificate`. A live
        certificate with the same CN is revoked and ``ca/crl.pem`` republished,
        unless ``keep_previous=True`` (see :meth:`add_certificate`). The entry
        records ``uri_san``.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_cert, ca_key = ca_material
        cert_pem, key_pem = generate_client_certificate(
            ca_cert,
            ca_key,
            common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            key_size=key_size,
            key_type=key_type,
            allow_long_validity=allow_long_validity,
            allow_dn_special_chars=allow_dn_special_chars,
            ocsp_url=self.ocsp_url,
            uri_san=uri_san,
        )
        return self._record(
            common_name, "client", cert_pem, key_pem, keep_previous=keep_previous, key_secret=key_secret
        )

    @_locked
    def issue_server(
        self,
        common_name: str,
        san_entries: list[str],
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
        key_size: int | None = None,
        key_type: KeyType = DEFAULT_KEY_TYPE,
        allow_long_validity: bool = False,
        include_common_name_in_sans: bool = True,
        allow_dn_special_chars: bool = False,
        key_secret: str | None = None,
    ) -> IssuedCertificate:
        """Issue and record a server certificate, as ``tiny-pki create server``.

        Arguments match :func:`tiny_pki.generate_server_certificate`. A live
        certificate with the same CN is revoked and ``ca/crl.pem`` republished.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_cert, ca_key = ca_material
        cert_pem, key_pem = generate_server_certificate(
            ca_cert,
            ca_key,
            common_name,
            san_entries,
            organization_name=organization_name,
            validity_days=validity_days,
            key_size=key_size,
            key_type=key_type,
            allow_long_validity=allow_long_validity,
            include_common_name_in_sans=include_common_name_in_sans,
            allow_dn_special_chars=allow_dn_special_chars,
            ocsp_url=self.ocsp_url,
        )
        return self._record(common_name, "server", cert_pem, key_pem, key_secret=key_secret)

    @_locked
    def sign_client_csr(
        self,
        common_name: str,
        csr_pem: bytes,
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
        allow_long_validity: bool = False,
        allow_dn_special_chars: bool = False,
        keep_previous: bool = False,
        key_secret: str | None = None,
        uri_san: str | None = None,
    ) -> IssuedCertificate:
        """Sign a device's CSR as a client certificate and record it, as ``tiny-pki sign client``.

        Arguments match :func:`tiny_pki.sign_client_csr`. The entry has no
        ``key_path``: the private key stays on the device. Replacement,
        ``keep_previous`` and CRL republishing behave as in :meth:`issue_client`.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_cert, ca_key = ca_material
        cert_pem = sign_client_csr(
            ca_cert,
            ca_key,
            csr_pem,
            common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            allow_long_validity=allow_long_validity,
            allow_dn_special_chars=allow_dn_special_chars,
            ocsp_url=self.ocsp_url,
            uri_san=uri_san,
        )
        return self._record(common_name, "client", cert_pem, None, keep_previous=keep_previous, key_secret=key_secret)

    @_locked
    def sign_server_csr(
        self,
        common_name: str,
        csr_pem: bytes,
        san_entries: list[str],
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_SERVER_VALIDITY_DAYS,
        allow_long_validity: bool = False,
        include_common_name_in_sans: bool = True,
        include_csr_sans: bool = False,
        allow_dn_special_chars: bool = False,
        key_secret: str | None = None,
    ) -> IssuedCertificate:
        """Sign a server's CSR as a server certificate and record it, as ``tiny-pki sign server``.

        Arguments match :func:`tiny_pki.sign_server_csr`. The entry has no
        ``key_path``: the private key stays on the server. Replacement and CRL
        republishing behave as in :meth:`issue_server`.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_cert, ca_key = ca_material
        cert_pem = sign_server_csr(
            ca_cert,
            ca_key,
            csr_pem,
            common_name,
            san_entries,
            organization_name=organization_name,
            validity_days=validity_days,
            allow_long_validity=allow_long_validity,
            include_common_name_in_sans=include_common_name_in_sans,
            include_csr_sans=include_csr_sans,
            allow_dn_special_chars=allow_dn_special_chars,
            ocsp_url=self.ocsp_url,
        )
        return self._record(common_name, "server", cert_pem, None, key_secret=key_secret)

    @_locked
    def issue_intermediate(
        self,
        common_name: str,
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
        key_size: int | None = None,
        key_type: KeyType = DEFAULT_KEY_TYPE,
        permitted_subtrees: list[str] | None = None,
        key_secret: str | None = None,
    ) -> tuple[IssuedCertificate, bytes]:
        """Issue an intermediate CA and record its certificate; the private key is returned, never stored here.

        Arguments match :func:`tiny_pki.generate_intermediate_ca_certificate`; the
        store's CA must have been created with ``path_length=1``. Hand the key to
        the intermediate's own store (:meth:`init_intermediate` does both steps).

        Returns:
            ``(entry, private_key_pem)``.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        cert_pem, key_pem = generate_intermediate_ca_certificate(
            *ca_material,
            common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            key_size=key_size,
            key_type=key_type,
            permitted_subtrees=permitted_subtrees,
        )
        return self._record(common_name, "intermediate", cert_pem, None, key_secret=key_secret), key_pem

    @_locked
    def sign_intermediate_csr(
        self,
        common_name: str,
        csr_pem: bytes,
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
        permitted_subtrees: list[str] | None = None,
        key_secret: str | None = None,
    ) -> IssuedCertificate:
        """Sign an intermediate CA's CSR and record it, as ``tiny-pki sign intermediate``.

        Arguments match :func:`tiny_pki.sign_intermediate_csr`. The intermediate
        needs this store's :meth:`read_ca_chain` next to its certificate, and this
        store's CRL, to be trusted by relying parties that check revocation.
        """
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        cert_pem = sign_intermediate_csr(
            *ca_material,
            csr_pem,
            common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            permitted_subtrees=permitted_subtrees,
        )
        return self._record(common_name, "intermediate", cert_pem, None, key_secret=key_secret)

    @_locked
    def init_intermediate(
        self,
        issuer: CertificateStore,
        common_name: str,
        *,
        organization_name: str | None = None,
        validity_days: int = DEFAULT_INTERMEDIATE_VALIDITY_DAYS,
        key_size: int | None = None,
        key_type: KeyType = DEFAULT_KEY_TYPE,
        permitted_subtrees: list[str] | None = None,
        key_secret: str | None = None,
        issuer_key_secret: str | None = None,
        crl_validity_days: int | None = None,
    ) -> IssuedCertificate:
        """Create this store's CA as an intermediate signed by ``issuer``, as ``tiny-pki init --intermediate-of``.

        ``issuer`` records the certificate (see :meth:`issue_intermediate`); this
        store gets the key (encrypted with ``key_secret`` when given), the chain,
        the issuer's CRLs (see :meth:`import_chain_crl`) and its own first CRL.
        If setting up this store fails after the issuer signed, the issuer
        revokes the new certificate and the CA files written here are removed,
        so no live intermediate is left without its key and a retry can start over.

        Returns:
            The issuer's index entry for the new intermediate.
        """
        if self.has_ca():
            raise ValueError(f"CA already exists under {self.root}")
        if issuer.root == self.root:
            raise ValueError("Expected the issuer to be a different store than the intermediate")
        if key_secret is not None:
            require_strong_secret(key_secret)
        if crl_validity_days is not None:
            _require_crl_validity_days(crl_validity_days)
        self.ensure_layout()
        ca_files = [
            self._validated_write_path(name)
            for name in (
                "ca/ca.crt",
                "ca/ca.key",
                "ca/chain.pem",
                "ca/chain-crl.pem",
                "ca/crl.pem",
                "ca/crldays",
                "ca/crlnumber",
                "public/ca.crt",
                "public/ca-chain.pem",
                "public/crl.pem",
            )
        ]
        preexisting = {path for path in ca_files if path.exists()}
        entry, key_pem = issuer.issue_intermediate(
            common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            key_size=key_size,
            key_type=key_type,
            permitted_subtrees=permitted_subtrees,
            key_secret=issuer_key_secret,
        )
        try:
            self.write_ca(
                issuer.read_certificate_pem(entry), key_pem, chain_pem=issuer.read_ca_chain(), key_secret=key_secret
            )
            for crl in (issuer.read_crl(), *issuer.read_chain_crls()):
                if crl is None:
                    continue
                self.import_chain_crl(crl)
            self.publish_crl(validity_days=crl_validity_days, key_secret=key_secret)
        except BaseException:
            for path in ca_files:
                if path not in preexisting:
                    path.unlink(missing_ok=True)
            materials: dict[Path, tuple[bytes, bytes]] = _HELD_LOCKS.__dict__.setdefault("ca_material", {})
            materials.pop(self.lock_path, None)
            issuer.revoke(f"0x{entry.serial_number}", key_secret=issuer_key_secret)
            raise
        return entry

    @_locked
    def import_chain_crl(self, crl_pem: bytes) -> None:
        """Store the CRL of a CA above this intermediate, and republish ``public/crl.pem`` with it.

        Run it whenever that CA publishes a new CRL (at least before the stored
        one reaches ``nextUpdate``): a TLS server that checks CRLs rejects every
        client once any CRL in the chain has expired. The CRL must be signed by
        a certificate in :attr:`ca_chain_path`, and it replaces an older CRL of
        the same CA, never a newer one.

        Raises:
            TinyPkiError: The store's CA is not an intermediate, the CRL is not
                signed by a CA in its chain, or its CRL number is lower than the
                stored one's.
        """
        try:
            crl = x509.load_pem_x509_crl(crl_pem)
        except ValueError as exc:
            raise TinyPkiError("Expected a PEM CRL to import into the chain") from exc
        chain = self._chain_certificates()
        if not chain:
            raise TinyPkiError(f"Expected an intermediate CA under {self.ca_dir}; a root CA has no chain CRLs")
        issuer = _crl_issuer(crl, chain)
        if issuer is None:
            names = ", ".join(cert.subject.rfc4514_string() for cert in chain)
            raise TinyPkiError(f"Expected a CRL signed by a CA in this store's chain ({names}), got {crl.issuer}")
        kept: list[bytes] = []
        for existing_pem in self.read_chain_crls():
            existing = x509.load_pem_x509_crl(existing_pem)
            if _crl_issuer(existing, [issuer]) is None:
                kept.append(existing_pem)
                continue
            old_number, new_number = _crl_number(existing_pem), _crl_number(crl_pem)
            if old_number is not None and (new_number is None or new_number < old_number):
                raise TinyPkiError(
                    f"Expected a CRL for {issuer.subject.rfc4514_string()} at least as new as the stored one "
                    f"(CRL number {old_number}), got CRL number {new_number}; refusing to roll it back"
                )
        kept.append(crl.public_bytes(serialization.Encoding.PEM))
        _write_plain(self._validated_write_path("ca/chain-crl.pem"), b"".join(kept))
        self._sync_public_dir()

    def read_ca_chain(self) -> bytes:
        """Return the CA certificate followed by its chain (:attr:`ca_chain_path`), as concatenated PEM.

        For a root CA that is just the CA certificate. Give it to relying
        parties (``ssl_trusted_certificate``) and to PKCS#12 bundles.
        """
        chain = self._validated_write_path("ca/chain.pem")
        return self.read_ca_certificate() + (chain.read_bytes() if chain.is_file() else b"")

    def read_chain_crls(self) -> list[bytes]:
        """Return the CRLs imported for the CAs above this intermediate (PEM each; empty for a root CA)."""
        path = self._validated_write_path("ca/chain-crl.pem")
        if not path.is_file():
            return []
        return [crl.public_bytes(serialization.Encoding.PEM) for crl in _load_pem_crls(path.read_bytes(), source=path)]

    def revoke(self, identity: str, *, key_secret: str | None = None) -> IssuedCertificate:
        """Revoke a certificate, as ``tiny-pki revoke``; see :meth:`mark_revoked`."""
        return self.mark_revoked(identity, key_secret=key_secret)

    def read_ca(self, *, key_secret: str | None = None) -> tuple[bytes, bytes]:
        """Return ``(ca_cert_pem, ca_key_pem)``, decrypting the key when required."""
        self._maybe_migrate_legacy_layout()
        if not self.ca_cert_path.is_file() or not self.ca_key_path.is_file():
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_key = self.ca_key_path.read_bytes()
        if ca_key.startswith(_ENCRYPTED_CA_KEY_PREFIX):
            if key_secret is None:
                raise TinyPkiError("The CA private key is encrypted; provide a key secret to use signing commands")
            try:
                ca_key = decrypt_private_key_scrypt(ca_key[len(_ENCRYPTED_CA_KEY_PREFIX) :], key_secret)
            except InvalidToken as exc:
                raise TinyPkiError("Could not unlock the CA private key; the supplied secret may be incorrect") from exc
        return self.ca_cert_path.read_bytes(), ca_key

    def read_ca_certificate(self) -> bytes:
        """Return the CA certificate without reading or unlocking its private key."""
        self._maybe_migrate_legacy_layout()
        if not self.ca_cert_path.is_file():
            raise FileNotFoundError(f"Expected a CA certificate under {self.ca_dir}")
        return self.ca_cert_path.read_bytes()

    @_locked
    def encrypt_ca_key(self, key_secret: str) -> None:
        """Encrypt a plaintext CA key in place while holding the store lock."""
        self.ensure_layout()
        if not self.ca_key_path.is_file():
            raise FileNotFoundError(f"Expected a CA private key under {self.ca_dir}")
        if self.ca_key_encrypted:
            raise ValueError("The CA private key is already encrypted")
        key_pem = self.ca_key_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(self.read_ca_certificate())
        load_ca_private_key(ca_cert, key_pem)
        encrypted = _ENCRYPTED_CA_KEY_PREFIX + encrypt_private_key_scrypt(key_pem, key_secret)
        write_file_atomic(self._validated_write_path("ca/ca.key"), encrypted, mode=0o600)

    @_locked
    def decrypt_ca_key(self, key_secret: str) -> None:
        """Decrypt an encrypted CA key in place while holding the store lock."""
        self.ensure_layout()
        if not self.ca_key_path.is_file():
            raise FileNotFoundError(f"Expected a CA private key under {self.ca_dir}")
        if not self.ca_key_encrypted:
            raise ValueError("The CA private key is not encrypted")
        stored_key = self.ca_key_path.read_bytes()
        if not stored_key.startswith(_ENCRYPTED_CA_KEY_PREFIX):
            raise ValueError("The CA private key is not encrypted")
        try:
            key_pem = decrypt_private_key_scrypt(stored_key[len(_ENCRYPTED_CA_KEY_PREFIX) :], key_secret)
        except InvalidToken as exc:
            raise TinyPkiError("Could not unlock the CA private key; the supplied secret may be incorrect") from exc
        ca_cert = x509.load_pem_x509_certificate(self.read_ca_certificate())
        load_ca_private_key(ca_cert, key_pem)
        write_file_atomic(self._validated_write_path("ca/ca.key"), key_pem, mode=0o600)

    def read_certificate_pem(self, entry: IssuedCertificate) -> bytes:
        if not entry.cert_path:
            raise FileNotFoundError(f"Expected on-disk certificate for {entry.common_name!r}")
        return self._validated_write_path(entry.cert_path).read_bytes()

    def read_crl(self) -> bytes | None:
        self._maybe_migrate_legacy_layout()
        if not self.crl_path.is_file():
            return None
        return self.crl_path.read_bytes()

    def read_key_pem(self, entry: IssuedCertificate) -> bytes:
        if not entry.key_path:
            raise FileNotFoundError(f"Expected on-disk key for {entry.common_name!r}")
        return self._validated_write_path(entry.key_path).read_bytes()

    def superseded_serials(self) -> dict[str, str]:
        """Map each live serial that a newer live certificate of the same CN and kind replaces to that newer serial.

        Only ``keep_previous`` rotation leaves such pairs; revoke the old serial
        once the device has the new certificate.
        """
        newest: dict[tuple[str, CertKind], str] = {}
        live = self.list_certificates(status="active")
        for entry in live:
            newest[entry.common_name.casefold(), entry.kind] = entry.serial_number
        return {
            entry.serial_number: newest[entry.common_name.casefold(), entry.kind]
            for entry in live
            if newest[entry.common_name.casefold(), entry.kind] != entry.serial_number
        }

    def revoked_entries(self) -> list[tuple[int, datetime]]:
        """Return ``(serial_int, revoked_at)`` for CRL generation (includes tombstones)."""
        result: list[tuple[int, datetime]] = []
        for entry in self._read_index():
            if entry.revoked_at is None:
                continue
            result.append((int(entry.serial_number, 16), datetime.fromisoformat(entry.revoked_at)))
        return result

    @_locked
    def write_bundle(self, common_name: str, p12_bytes: bytes, *, serial_number: str | None = None) -> Path:
        """Write a PKCS#12 bundle under ``bundles/`` with mode 0600.

        The filename includes the certificate serial so distinct identities that
        sanitize to the same basename do not overwrite each other. When
        ``serial_number`` is omitted, the live index entry for ``common_name``
        supplies it. Serial must be hex digits only.
        """
        self.ensure_layout()
        serial = serial_number
        if serial is None:
            entry = self.get_certificate(common_name)
            if entry is None:
                raise KeyError(f"Expected issued certificate matching {common_name!r}")
            serial = entry.serial_number
        if not serial or any(ch not in "0123456789abcdefABCDEF" for ch in serial):
            raise ValueError(f"Expected hex serial_number, got {serial!r}")
        rel = f"bundles/{_safe_filename(common_name)}-{serial.lower()}.p12"
        path = self._validated_write_path(rel)
        _write_secret(path, p12_bytes)
        return path

    @_locked
    def write_ca(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        *,
        chain_pem: bytes | None = None,
        force: bool = False,
        key_secret: str | None = None,
    ) -> None:
        """Persist the CA certificate and private key (key mode 0600).

        ``chain_pem`` makes the CA an intermediate: the certificates above it,
        issuer first and self-signed root last, each of which must have signed the
        one before and be allowed to (a CA whose Key Usage, when present, has
        ``keyCertSign`` and whose ``path_length`` covers the CAs below it). The CA's
        own Name Constraints must be at least as narrow as every chain
        certificate's, since issuance and ``check`` enforce only the CA's own.
        Any previously imported chain CRLs are dropped (import the new
        issuers' CRLs with :meth:`import_chain_crl`). Refuses to overwrite an
        existing CA unless ``force=True``.

        Raises:
            TinyPkiError: ``chain_pem`` does not lead from ``cert_pem`` to a self-signed root.
        """
        if chain_pem is not None:
            chain_pem = _validated_chain(cert_pem, chain_pem)
        # Migrate first so legacy root CA material is visible to has_ca().
        self.ensure_layout()
        existing_ca = self.has_ca()
        if existing_ca and not force:
            raise ValueError(f"CA already exists under {self.root}; pass force=True to replace")
        if existing_ca and self.ca_key_encrypted and key_secret is None:
            raise TinyPkiError("Replacing an encrypted CA requires key_secret so the replacement stays encrypted")
        stored_key = key_pem
        if key_secret is not None:
            stored_key = _ENCRYPTED_CA_KEY_PREFIX + encrypt_private_key_scrypt(key_pem, key_secret)
        _write_plain(self._validated_write_path("ca/ca.crt"), cert_pem)
        _write_secret(self._validated_write_path("ca/ca.key"), stored_key)
        self._validated_write_path("ca/chain-crl.pem").unlink(missing_ok=True)
        if chain_pem is None:
            self._validated_write_path("ca/chain.pem").unlink(missing_ok=True)
        else:
            _write_plain(self._validated_write_path("ca/chain.pem"), chain_pem)
        self._sync_public_dir()
        materials: dict[Path, tuple[bytes, bytes]] = _HELD_LOCKS.__dict__.setdefault("ca_material", {})
        materials.pop(self.lock_path, None)

    @_locked
    def write_crl(self, crl_pem: bytes) -> None:
        """Publish ``crl_pem`` as ``ca/crl.pem`` and record its CRL number.

        The number is recorded first, so a crash between the two writes can only
        make the next number larger, never reuse one.
        """
        self.ensure_layout()
        number = _crl_number(crl_pem)
        if number is not None and number > self._recorded_crl_number():
            _write_plain(self._validated_write_path("ca/crlnumber"), f"{number}\n".encode())
        _write_plain(self._validated_write_path("ca/crl.pem"), crl_pem)
        self._sync_public_dir()

    def next_crl_number(self, *, now: datetime | None = None) -> int:
        """Return a CRL number above every one this store has published.

        Uses microseconds since the epoch while the clock moves forward (the
        library default) and ``last + 1`` when it does not, so a backward clock
        step cannot publish a lower number.
        """
        current = self.read_crl()
        on_disk = _crl_number(current) if current is not None else None
        last = max(self._recorded_crl_number(), on_disk or 0)
        clock = ((now or datetime.now(UTC)) - _EPOCH) // timedelta(microseconds=1)
        number = max(clock, last + 1)
        if number > _MAX_CRL_NUMBER:
            raise ValueError(f"Expected a CRL number below 2**159 in {self.ca_dir}, but {last} was already published")
        return number

    def _record(
        self,
        common_name: str,
        kind: CertKind,
        cert_pem: bytes,
        key_pem: bytes | None,
        *,
        keep_previous: bool = False,
        key_secret: str | None = None,
    ) -> IssuedCertificate:
        return self.add_certificate(
            common_name=common_name,
            kind=kind,
            serial_number=get_certificate_serial_number(cert_pem),
            cert_pem=cert_pem,
            key_pem=key_pem,
            not_valid_after=get_certificate_expiry(cert_pem),
            fingerprint=get_certificate_fingerprint(cert_pem),
            keep_previous=keep_previous,
            key_secret=key_secret,
            uri_san=next(iter(get_certificate_uris(cert_pem)), None),
        )

    def _require_ca_signing_key(self, key_secret: str | None) -> tuple[bytes, bytes] | None:
        if not self.has_ca():
            return None
        depth: dict[Path, int] = _HELD_LOCKS.__dict__.setdefault("depth", {})
        materials: dict[Path, tuple[bytes, bytes]] = _HELD_LOCKS.__dict__.setdefault("ca_material", {})
        if depth.get(self.lock_path):
            cached = materials.get(self.lock_path)
            if cached is not None:
                return cached
        ca_cert_pem, ca_key_pem = self.read_ca(key_secret=key_secret)
        load_ca_private_key(x509.load_pem_x509_certificate(ca_cert_pem), ca_key_pem)
        material = (ca_cert_pem, ca_key_pem)
        if depth.get(self.lock_path):
            materials[self.lock_path] = material
        return material

    def _republish_crl(self, changed: IssuedCertificate, *, key_secret: str | None = None) -> None:
        """Re-sign the CRL after ``changed`` was issued, revoked or deleted, refreshing only its OCSP responses."""
        if not self.has_ca():
            return
        _, ca_cert, ca_key = self._sign_and_write_crl(None, key_secret)
        ocsp_days = self.ocsp_validity_days
        if ocsp_days is not None and changed.kind == "server":
            self._write_ocsp_responses(ca_cert, ca_key, ocsp_days, only=_safe_filename(changed.common_name))

    def _sign_and_write_crl(self, validity_days: int | None, key_secret: str | None) -> tuple[bytes, bytes, bytes]:
        """Publish a fresh CRL; return it with the CA material that signed it."""
        days = self.crl_validity_days if validity_days is None else _require_crl_validity_days(validity_days)
        ca_material = self._require_ca_signing_key(key_secret)
        if ca_material is None:
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        ca_cert, ca_key = ca_material
        crl = generate_crl(
            ca_cert,
            ca_key,
            self.revoked_entries(),
            validity_days=days,
            crl_number=self.next_crl_number(),
        )
        self.write_crl(crl)
        if validity_days is not None:
            self.set_crl_validity_days(validity_days)
        return crl, ca_cert, ca_key

    def _write_ocsp_responses(
        self, ca_cert_pem: bytes, ca_key_pem: bytes, days: int, *, only: str | None = None
    ) -> list[Path]:
        """Replace ``public/ocsp/*.der`` with fresh responses for the server certificates still on disk.

        ``only`` (a :func:`_safe_filename` of a CN) limits the refresh to the
        files of that name, leaving every other response as it is.
        Certificates the current CA did not issue (left over from a CA replaced
        with ``write_ca(force=True)``) get no response, so they cannot block a
        CRL publish.
        """
        groups: dict[str, list[IssuedCertificate]] = {}
        for entry in self.list_certificates(kind="server", status="all"):
            groups.setdefault(_safe_filename(entry.common_name), []).append(entry)
        if only is not None:
            groups = {only: groups.get(only, [])}
        revoked = self.revoked_entries()
        responses: dict[str, bytes] = {}
        for safe, group in groups.items():
            primary = _stable_ocsp_entry(group)
            for entry in group:
                filename = f"{safe}.der" if entry is primary else f"{safe}-{entry.serial_number}.der"
                try:
                    responses[filename] = generate_ocsp_response_for_certificate(
                        ca_cert_pem,
                        ca_key_pem,
                        self.read_certificate_pem(entry),
                        revoked_entries=revoked,
                        validity_days=days,
                    )
                except ForeignCertificateError:
                    continue
        directory = self._validated_write_path("public/ocsp")
        if not directory.exists():
            directory.mkdir(mode=_PUBLIC_DIR_MODE)
        elif not directory.is_dir():
            raise ValueError(f"Expected {directory} to be a directory for the OCSP responses")
        _set_owned_mode(directory, _PUBLIC_DIR_MODE)
        written: list[Path] = []
        for filename, response in sorted(responses.items()):
            path = self._validated_write_path(f"public/ocsp/{filename}")
            _write_plain(path, response)
            written.append(path)
        if only is None:
            stale = [path for path in directory.iterdir() if path.suffix == ".der"]
        else:
            owned = {f"{only}.der"} | {
                f"{only}-{entry.serial_number}.der"
                for entry in self._read_index()
                if entry.kind == "server" and _safe_filename(entry.common_name) == only
            }
            stale = [directory / name for name in owned]
        for path in stale:
            if path.name not in responses:
                path.unlink(missing_ok=True)
        return written

    def _chain_certificates(self) -> list[x509.Certificate]:
        path = self._validated_write_path("ca/chain.pem")
        if not path.is_file():
            return []
        return x509.load_pem_x509_certificates(path.read_bytes())

    def _recorded_crl_number(self) -> int:
        path = self._validated_write_path("ca/crlnumber")
        if not path.is_file():
            return 0
        text = path.read_text(encoding="utf-8").strip()
        if not text.isdigit():
            raise ValueError(f"Expected a decimal CRL number in {path}")
        return int(text)

    def _is_legacy_layout(self) -> bool:
        """True when any flat-root CA material or ``certs/`` index paths remain."""
        if (self.root / "ca.crt").is_file() and not self.ca_cert_path.is_file():
            return True
        if (self.root / "ca.key").is_file() and not self.ca_key_path.is_file():
            return True
        if (self.root / "crl.pem").is_file() and not self.crl_path.is_file():
            return True
        if (self.root / "index.json").is_file() and not self.index_path.is_file():
            return True
        # Mid-migration: typed CA present but index still references certs/.
        for index in (self.index_path, self.root / "index.json"):
            if index.is_file() and _index_references_certs_paths(index):
                return True
        return False

    def _maybe_migrate_legacy_layout(self) -> None:
        if self._is_legacy_layout():
            with self.lock():
                if self._is_legacy_layout():
                    self._migrate_legacy_layout()

    def _migrate_legacy_layout(self) -> None:
        """Move flat-root CA material and ``certs/`` leaves into the typed tree.

        Order is re-entrant: rewrite leaves + index under ``ca/`` first, then move
        CA PEMs last so a mid-migration failure still leaves ``_is_legacy_layout``
        true and a later open can finish the job.
        """
        self._make_subdirs()

        root_index = self.root / "index.json"
        index_source = self.index_path if self.index_path.is_file() else root_index
        migrated: list[IssuedCertificate] = []
        if index_source.is_file():
            raw: Any = json.loads(index_source.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError(f"Expected index.json to be a list, got {type(raw).__name__}")
            for item in cast(list[Any], raw):
                entry = _entry_from_dict(item)
                cert_rel = entry.cert_path
                key_rel = entry.key_path
                if cert_rel.startswith("certs/"):
                    # Reject traversal / non-certs keys before any shutil.move.
                    if key_rel and not key_rel.startswith("certs/"):
                        raise ValueError(f"Expected legacy key_path under certs/, got {key_rel!r}")
                    old_cert = self._path_under_root(cert_rel)
                    old_key = self._path_under_root(key_rel) if key_rel else None
                    leaf_dir = _CERT_DIRS[entry.kind]
                    new_cert = f"{leaf_dir}/{Path(cert_rel).name}"
                    new_key = f"{leaf_dir}/{Path(key_rel).name}" if key_rel else ""
                    if old_cert.is_file():
                        dest_cert = self._path_under_root(new_cert)
                        dest_cert.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
                        if not dest_cert.exists():
                            shutil.move(str(old_cert), str(dest_cert))
                    if old_key is not None and old_key.is_file() and new_key:
                        dest_key = self._path_under_root(new_key)
                        dest_key.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
                        if not dest_key.exists():
                            shutil.move(str(old_key), str(dest_key))
                    entry = replace(entry, cert_path=new_cert if cert_rel else "", key_path=new_key if key_rel else "")
                self._check_index_paths(entry)
                migrated.append(entry)
            self._write_index(migrated)
            if root_index.is_file() and root_index.resolve() != self.index_path.resolve():
                root_index.unlink(missing_ok=True)

        for name in ("ca.crt", "ca.key", "crl.pem"):
            src = self.root / name
            if src.is_file():
                dest = self._validated_write_path(f"ca/{name}")
                if not dest.exists():
                    shutil.move(str(src), str(dest))

        legacy_certs = self.root / "certs"
        if legacy_certs.is_dir() and not any(legacy_certs.iterdir()):
            legacy_certs.rmdir()
        self._sync_public_dir()

    def _path_under_root(self, relative: str) -> Path:
        """Resolve an index-relative path and require it stay under the store root."""
        if not relative or relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
            raise ValueError(f"Expected a relative path under the store root, got {relative!r}")
        resolved = (self.root / relative).resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"Expected path under store root {self.root}, got {resolved}") from exc
        return resolved

    def _validated_write_path(self, relative: str) -> Path:
        """Resolve ``relative`` under the store root, refusing a symlink anywhere in it.

        Used for every write and for leaf reads, so an in-store symlink can
        neither redirect a write onto ``ca/ca.key`` nor make ``export`` read it.

        ``_path_under_root`` alone only rejects a symlink whose *target*
        escapes the store root — a symlink at any component of ``relative``
        (leaf or intermediate directory, e.g. ``ca`` or ``ca.key``) whose
        target still resolves inside the root would pass it. Since the
        caller then writes through the *resolved* path, ``_open_new_file``'s
        own symlink check never sees the original symlink either — it only
        ever inspects the final component too, and by then that component
        is already the resolved (non-symlink) target. Walking every
        component of the *unresolved* path and checking ``is_symlink()``
        catches a symlink anywhere, regardless of where it points, before
        any of it is resolved.
        """
        current = self.root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"Expected {current} to not already exist as a symlink")
        return self._path_under_root(relative)

    def _read_index(self) -> list[IssuedCertificate]:
        self._maybe_migrate_legacy_layout()
        if not self.index_path.is_file():
            if self.ca_cert_path.is_file() and self.ca_key_path.is_file():
                raise FileNotFoundError(f"Expected index.json under {self.ca_dir} (CA present but index missing)")
            return []
        raw: Any = json.loads(self.index_path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"Expected index.json to be a list, got {type(raw).__name__}")
        entries = [_entry_from_dict(item) for item in cast(list[Any], raw)]
        for entry in entries:
            self._check_index_paths(entry)
        return entries

    def _check_index_paths(self, entry: IssuedCertificate) -> None:
        """Reject index paths that could point a leaf read or delete at CA material."""
        for rel, suffix in ((entry.cert_path, ".crt"), (entry.key_path, ".key")):
            if not rel:
                continue
            self._path_under_root(rel)
            parts = Path(rel).parts
            if len(parts) != 2 or parts[0] != _CERT_DIRS[entry.kind] or not parts[1].endswith(suffix):
                raise ValueError(f"Expected index path {_CERT_DIRS[entry.kind]}/<file>{suffix}, got {rel!r}")
            if entry.kind == "intermediate" and suffix == ".key":
                raise ValueError(f"Expected no key path for intermediate CA {entry.common_name!r}, got {rel!r}")
            if parts[1] == "ca.key":
                raise ValueError(f"Expected index path to not name the CA key, got {rel!r}")

    def _make_subdirs(self) -> None:
        for directory in (self.ca_dir, self.clients_dir, self.servers_dir, self.bundles_dir):
            directory.mkdir(mode=_DIR_MODE, exist_ok=True)
        public = self._validated_write_path("public")
        if not public.exists():
            public.mkdir(mode=_PUBLIC_DIR_MODE)
        elif not public.is_dir():
            raise ValueError(f"Expected {public} to be a directory for the public CA certificate and CRL")
        _set_owned_mode(public, _PUBLIC_DIR_MODE)

    def _sync_public_dir(self) -> None:
        """Bring ``public/`` up to date with ``ca/`` (fills it in for stores created before it existed).

        ``crl.pem`` is the own CRL plus the chain CRLs, and ``ca-chain.pem`` (the CA
        certificate plus its chain) exists only for an intermediate CA.
        """
        ca_dir = self._validated_write_path("ca")
        ca_cert, crl, chain, chain_crls = (
            path.read_bytes() if path.is_file() else None
            for path in (ca_dir / "ca.crt", ca_dir / "crl.pem", ca_dir / "chain.pem", ca_dir / "chain-crl.pem")
        )
        published: dict[str, bytes | None] = {
            "ca.crt": ca_cert,
            "crl.pem": None if crl is None else crl + (chain_crls or b""),
            "ca-chain.pem": None if ca_cert is None or chain is None else ca_cert + chain,
        }
        for name, data in published.items():
            target = self._validated_write_path(f"public/{name}")
            if data is None:
                if name == "ca-chain.pem":
                    target.unlink(missing_ok=True)
                continue
            if (
                not target.is_file()
                or stat.S_IMODE(target.lstat().st_mode) != _PUBLIC_FILE_MODE
                or target.read_bytes() != data
            ):
                _write_plain(target, data)

    def _write_index(self, entries: list[IssuedCertificate]) -> None:
        self.ca_dir.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        payload = [{k: v for k, v in asdict(e).items() if k != "uri_san" or v is not None} for e in entries]
        _write_secret(
            self._validated_write_path("ca/index.json"),
            (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )


def check_store(
    store: CertificateStore,
    *,
    within: timedelta | None = None,
    by: datetime | None = None,
    kinds: set[CheckKind] | frozenset[CheckKind] = CHECK_KINDS,
    include_revoked: bool = False,
) -> list[tuple[str, CertificateStatus]]:
    """Check the CA, the CRL, and every issued leaf, as ``tiny-pki check`` does for a store.

    ``index.json`` is authoritative: a CRL missing a serial it records as revoked
    is ``untrusted`` (reported even when ``kinds`` leaves out ``"crl"``), and a leaf
    it records as revoked is ``revoked`` even if the CRL omits it. Revoked leaves
    are listed only with ``include_revoked=True``. A live leaf that a newer live
    certificate for the same CN replaces is named ``"<cn> (superseded, 0x<serial>)"``
    with a reason naming the newer serial.

    For an intermediate CA, the CA is checked against its issuer (and the
    issuer's imported CRL), and each chain certificate gets an ``"issuer <cn>"``
    row (kind ``"ca"``) and each chain CRL an ``"issuer crl <cn>"`` row (kind
    ``"crl"``); a missing chain CRL is ``untrusted``. Intermediate CAs this CA
    signed are checked as kind ``"ca"``.

    Returns:
        ``(name, status)`` rows: ``"ca"``, ``"crl"``, then each leaf by common name.

    Raises:
        FileNotFoundError: The CA certificate is missing, or the CRL is missing
            while the index records revocations.
    """
    crl_pem = store.read_crl()
    if not store.ca_cert_path.is_file():
        raise FileNotFoundError(f"Expected a CA certificate at {store.ca_cert_path}")
    ca_cert = store.ca_cert_path.read_bytes()
    chain = [
        cert.public_bytes(serialization.Encoding.PEM) for cert in x509.load_pem_x509_certificates(store.read_ca_chain())
    ][1:]
    rows = _chain_rows(ca_cert, chain, store.read_chain_crls(), within=within, by=by, kinds=kinds)
    index_revoked = {int(e.serial_number, 16) for e in store.list_certificates(status="revoked")}
    trusted_crl: bytes | None = None
    if crl_pem is None:
        if index_revoked:
            raise FileNotFoundError(
                f"Expected a CRL at {store.crl_path} listing {len(index_revoked)} serial(s) revoked in index.json"
            )
    else:
        crl_result = check_crl(crl_pem, within=within, by=by, ca_cert_pem=ca_cert)
        if crl_result.status is not Status.UNTRUSTED:
            trusted_crl = crl_pem
            listed = {r.serial_number for r in x509.load_pem_x509_crl(crl_pem)}
            missing = sorted(index_revoked - listed)
            if missing:
                shown = ", ".join(format(s, "x") for s in missing[:5]) + (" ..." if len(missing) > 5 else "")
                crl_result = _escalate(
                    crl_result,
                    Status.UNTRUSTED,
                    f"missing {len(missing)} serial(s) revoked in index.json ({shown}); republish with `crl`",
                )
        if "crl" in kinds or crl_result.status is Status.UNTRUSTED:
            rows.append(("crl", crl_result))
    superseded = store.superseded_serials()
    for entry in store.list_certificates(status="all" if include_revoked else "active"):
        if ("ca" if entry.kind == "intermediate" else entry.kind) not in kinds:
            continue
        cert_pem = store.read_certificate_pem(entry)
        result = check_certificate(cert_pem, within=within, by=by, ca_cert_pem=ca_cert, crl_pem=trusted_crl)
        if entry.revoked_at is not None and result.status is not Status.REVOKED:
            result = _escalate(result, Status.REVOKED, f"revoked in index.json on {entry.revoked_at}")
        name = entry.common_name
        newer = superseded.get(entry.serial_number)
        if newer is not None:
            name = f"{entry.common_name} (superseded, 0x{entry.serial_number})"
            result = replace(
                result,
                reasons=(
                    *result.reasons,
                    f"superseded by serial {newer}; revoke 0x{entry.serial_number} once the device has the new one",
                ),
            )
        rows.append((name, result))
    return rows


def _chain_rows(
    ca_cert: bytes,
    chain: list[bytes],
    chain_crls: list[bytes],
    *,
    within: timedelta | None,
    by: datetime | None,
    kinds: set[CheckKind] | frozenset[CheckKind],
) -> list[tuple[str, CertificateStatus]]:
    """Rows for the store CA and, for an intermediate, every certificate and CRL above it."""
    crl_by_issuer: dict[bytes, bytes] = {}
    for crl_pem in chain_crls:
        crl = x509.load_pem_x509_crl(crl_pem)
        for issuer_pem in chain:
            if _crl_issuer(crl, [x509.load_pem_x509_certificate(issuer_pem)]) is not None:
                crl_by_issuer[issuer_pem] = crl_pem
    rows: list[tuple[str, CertificateStatus]] = []
    for position, cert_pem in enumerate([ca_cert, *chain]):
        issuer_pem = chain[position] if position < len(chain) else cert_pem
        if "ca" in kinds:
            result = check_certificate(
                cert_pem,
                within=within,
                by=by,
                ca_cert_pem=issuer_pem,
                crl_pem=crl_by_issuer.get(issuer_pem) if issuer_pem != cert_pem else None,
            )
            rows.append(("ca" if position == 0 else f"issuer {_subject_cn(cert_pem)}", result))
        if position == 0:
            continue
        name = f"issuer crl {_subject_cn(cert_pem)}"
        crl_pem = crl_by_issuer.get(cert_pem)
        if crl_pem is None:
            now = datetime.now(UTC)
            label = x509.load_pem_x509_certificate(cert_pem).subject.rfc4514_string()
            rows.append(
                (
                    name,
                    CertificateStatus(
                        kind="crl",
                        subject=label,
                        issuer=label,
                        serial_number=None,
                        not_before=now,
                        not_after=None,
                        cutoff=now,
                        days_remaining=None,
                        status=Status.UNTRUSTED,
                        reasons=("missing; import the issuer's current CRL with `crl --chain-crl PATH`",),
                    ),
                )
            )
            continue
        crl_result = check_crl(crl_pem, within=within, by=by, ca_cert_pem=cert_pem)
        if "crl" in kinds or crl_result.status is Status.UNTRUSTED:
            rows.append((name, crl_result))
    return rows


def _escalate(result: CertificateStatus, status: Status, reason: str) -> CertificateStatus:
    """Add ``reason`` to ``result``, raising its status to ``status`` if that is worse."""
    worst = max(result.status, status, key=lambda s: s.severity)
    return replace(result, status=worst, reasons=(*result.reasons, reason))


def require_store_path(path: Path | str | None) -> Path:
    """Validate an explicit store path for write operations."""
    if path is None:
        raise ValueError("Expected an explicit store path (--store / TINY_PKI_STORE)")
    text = str(path).strip()
    if not text or text == ".":
        raise ValueError("Expected an explicit store path (--store / TINY_PKI_STORE)")
    return Path(text).expanduser().resolve()


def _entry_from_dict(item: Any) -> IssuedCertificate:
    if not isinstance(item, Mapping):
        raise ValueError(f"Expected index entry object, got {type(item).__name__}")
    data = cast(Mapping[str, Any], item)
    kind = data.get("kind")
    if kind not in _CERT_DIRS:
        raise ValueError(f"Expected kind 'client', 'intermediate' or 'server', got {kind!r}")
    typed_kind = cast(CertKind, kind)
    revoked_raw = data.get("revoked_at")
    uri_raw = data.get("uri_san")
    return IssuedCertificate(
        common_name=str(data["common_name"]),
        kind=typed_kind,
        serial_number=str(data["serial_number"]),
        cert_path=str(data["cert_path"]),
        key_path=str(data["key_path"]),
        not_valid_after=str(data["not_valid_after"]),
        fingerprint=str(data["fingerprint"]),
        revoked_at=None if revoked_raw is None else str(revoked_raw),
        uri_san=None if uri_raw is None else str(uri_raw),
    )


def _index_references_certs_paths(index_path: Path) -> bool:
    """Return True when any index entry still uses a legacy ``certs/`` path."""
    try:
        raw: Any = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, list):
        return False
    for item in cast(list[Any], raw):
        if not isinstance(item, Mapping):
            continue
        data = cast(Mapping[str, Any], item)
        cert_path = str(data.get("cert_path", ""))
        key_path = str(data.get("key_path", ""))
        if cert_path.startswith("certs/") or key_path.startswith("certs/"):
            return True
    return False


_CERT_DIRS: dict[str, str] = {"client": "clients", "intermediate": "intermediates", "server": "servers"}
_DIR_MODE = 0o700
_PUBLIC_DIR_MODE = 0o755
_PUBLIC_FILE_MODE = 0o644
_ENCRYPTED_CA_KEY_PREFIX = b"TINY-PKI-ENCRYPTED-CA-KEY-V1\n"
# Per-thread lock depth keyed by lock path; flock is per open file, so a nested
# lock() in the same thread must reuse the held lock instead of opening another.
_HELD_LOCKS = threading.local()
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# RFC 5280 §5.2.3: conforming CRL numbers fit in 20 octets.
_MAX_CRL_NUMBER = 2**159 - 1


def _crl_issuer(crl: x509.CertificateRevocationList, candidates: list[x509.Certificate]) -> x509.Certificate | None:
    """The candidate whose subject and key signed ``crl``, if any."""
    for cert in candidates:
        if cert.subject != crl.issuer:
            continue
        try:
            if crl.is_signature_valid(cast(CertificateIssuerPublicKeyTypes, cert.public_key())):
                return cert
        except TypeError:
            continue
    return None


def _crl_number(crl_pem: bytes) -> int | None:
    try:
        crl = x509.load_pem_x509_crl(crl_pem)
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except (ValueError, x509.ExtensionNotFound):
        return None


def _require_crl_validity_days(days: object) -> int:
    """Return ``days`` if it is a plain int in range; bool and float would not round-trip through ``ca/crldays``."""
    if isinstance(days, bool) or not isinstance(days, int):
        raise TinyPkiError(f"Expected a whole number of days for the CRL lifetime, got {days!r}")
    if not 1 <= days <= MAX_STORE_CRL_VALIDITY_DAYS:
        raise TinyPkiError(f"Expected a CRL lifetime between 1 and {MAX_STORE_CRL_VALIDITY_DAYS} days, got {days}")
    return days


def _require_ocsp_validity_days(days: object) -> int:
    """Return ``days`` if it is a plain int in range, as :func:`_require_crl_validity_days` does for CRLs."""
    if isinstance(days, bool) or not isinstance(days, int):
        raise TinyPkiError(f"Expected a whole number of days for the OCSP response lifetime, got {days!r}")
    if not 1 <= days <= MAX_OCSP_VALIDITY_DAYS:
        raise TinyPkiError(
            f"Expected an OCSP response lifetime between 1 and {MAX_OCSP_VALIDITY_DAYS} days, got {days}"
        )
    return days


def _drop_world_write(directory: Path) -> None:
    """Strip other-write from a store directory we own.

    Group write is left alone (a deliberately shared store), as is read access
    (TLS servers reading ``ca/crl.pem``); directories owned by someone else are
    skipped because only the owner can chmod them, and a symlink is never
    followed so a planted link cannot redirect the chmod onto its target.
    """
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode):
        return
    getuid = getattr(os, "getuid", None)
    if info.st_mode & 0o002 and getuid is not None and info.st_uid == getuid():
        directory.chmod(stat.S_IMODE(info.st_mode) & ~0o002)


def _set_owned_mode(directory: Path, mode: int) -> None:
    """Set ``directory`` to exactly ``mode`` when we own it, so a TLS server can read it but not write it."""
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) == mode:
        return
    getuid = getattr(os, "getuid", None)
    if getuid is None or info.st_uid == getuid():
        directory.chmod(mode)


def _load_pem_crls(data: bytes, *, source: Path) -> list[x509.CertificateRevocationList]:
    marker = b"-----END X509 CRL-----"
    blocks = [block + marker for block in data.split(marker) if block.strip()]
    try:
        return [x509.load_pem_x509_crl(block) for block in blocks]
    except ValueError as exc:
        raise ValueError(f"Expected concatenated PEM CRLs in {source}") from exc


def _make_private_dir(directory: Path) -> None:
    if not directory.exists():
        directory.mkdir(mode=_DIR_MODE)
    elif not directory.is_dir():
        raise ValueError(f"Expected {directory} to be a directory")


def _stable_ocsp_entry(group: list[IssuedCertificate]) -> IssuedCertificate | None:
    """The entry that owns ``<cn>.der``: the newest live one, or the newest one when none is live.

    ``group`` is in index (issue) order and shares one file name; when it holds
    more than one CN, no entry owns the bare name, so none answers for another CN.
    """
    if not group or len({entry.common_name for entry in group}) > 1:
        return None
    live = [entry for entry in group if entry.revoked_at is None]
    return (live or group)[-1]


def _safe_filename(common_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in common_name.strip())
    if not cleaned:
        raise ValueError("Expected a common_name that yields a non-empty filename")
    return cleaned


# Callers resolve the target through _validated_write_path first, which rejects
# a symlink at any component. write_file_atomic then refuses a symlink at the
# final path and publishes via rename(2), which replaces a link planted in the
# meantime instead of writing through it; readers never see a truncated file.
def _subject_cn(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def _validated_chain(cert_pem: bytes, chain_pem: bytes) -> bytes:
    """Return ``chain_pem`` normalized, after checking it links ``cert_pem`` to a self-signed root."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        chain = x509.load_pem_x509_certificates(chain_pem)
    except ValueError as exc:
        raise TinyPkiError("Expected PEM certificates for the CA and its chain") from exc
    links = [cert, *chain]
    for depth, (child, parent) in enumerate(zip(links, [*chain, chain[-1]], strict=True)):
        try:
            constraints = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            constraints = None
        try:
            usage = parent.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            usage = None
        try:
            if constraints is None or not constraints.ca:
                raise ValueError("not a CA certificate")
            if usage is not None and not usage.key_cert_sign:
                raise ValueError("its Key Usage does not allow keyCertSign")
            # The CA certificates below ``parent`` (this store's CA included) all count against its path_length.
            if child is not parent and constraints.path_length is not None and constraints.path_length < depth + 1:
                raise ValueError(
                    f"its path_length={constraints.path_length} allows fewer than the "
                    f"{depth + 1} CA certificate(s) below it"
                )
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise TinyPkiError(
                f"Expected {child.subject.rfc4514_string()} to be issued by the next chain certificate "
                f"{parent.subject.rfc4514_string()} (chain: issuer first, self-signed root last): {exc}"
            ) from exc
    for ancestor in chain:
        require_name_constraints_within(cert, ancestor)
    return b"".join(link.public_bytes(serialization.Encoding.PEM) for link in chain)


def _write_plain(path: Path, data: bytes) -> None:
    """Atomically write non-secret bytes (cert/CRL) with mode 0644."""
    write_file_atomic(path, data, mode=0o644)


def _write_secret(path: Path, data: bytes) -> None:
    """Atomically write secret bytes (keys/bundles/index) with mode 0600."""
    write_file_atomic(path, data, mode=0o600)
