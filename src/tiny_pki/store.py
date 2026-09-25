"""Filesystem store for CLI-managed certificate authorities.

Writes require an explicit store directory (``--store`` / ``TINY_PKI_STORE``).
Private key files are created with mode ``0o600``.

Layout (one CA per store root)::

    $STORE/
      ca/ca.crt  ca/ca.key  ca/crl.pem  ca/index.json
      clients/{cn}-{serial}.{crt,key}
      servers/{cn}-{serial}.{crt,key}
      bundles/{cn}-{serial}.p12

Legacy flat layouts (``ca.crt`` / ``certs/`` at the store root) are migrated
automatically on first ``ensure_layout``.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

CertKind = Literal["client", "server"]
CertStatus = Literal["active", "all", "revoked"]


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
    def ca_dir(self) -> Path:
        return self.root / "ca"

    @property
    def ca_key_path(self) -> Path:
        return self.root / "ca" / "ca.key"

    @property
    def clients_dir(self) -> Path:
        return self.root / "clients"

    @property
    def crl_path(self) -> Path:
        return self.root / "ca" / "crl.pem"

    @property
    def index_path(self) -> Path:
        return self.root / "ca" / "index.json"

    @property
    def servers_dir(self) -> Path:
        return self.root / "servers"

    def add_certificate(
        self,
        *,
        common_name: str,
        kind: CertKind,
        serial_number: int,
        cert_pem: bytes,
        key_pem: bytes,
        not_valid_after: datetime,
        fingerprint: str,
    ) -> IssuedCertificate:
        """Write cert/key PEMs and append an index entry.

        Revoked tombstones for the same common name are retained for CRL generation.
        Re-issuing under an existing live CN auto-revokes the superseded serial.
        """
        self.ensure_layout()
        if kind not in ("client", "server"):
            raise ValueError(f"Expected kind 'client' or 'server', got {kind!r}")
        common_name = common_name.strip()
        if not common_name:
            raise ValueError("Expected a non-empty common_name")
        serial_hex = format(serial_number, "x")
        for existing in self._read_index():
            if existing.serial_number == serial_hex and existing.revoked_at is not None:
                raise ValueError(f"Serial {serial_hex} is already revoked; refuse to re-issue under that serial")
        leaf_dir = "clients" if kind == "client" else "servers"
        safe = _safe_filename(common_name)
        cert_rel = f"{leaf_dir}/{safe}-{serial_hex}.crt"
        key_rel = f"{leaf_dir}/{safe}-{serial_hex}.key"
        cert_path = self._path_under_root(cert_rel)
        key_path = self._path_under_root(key_rel)
        cert_path.write_bytes(cert_pem)
        _write_secret(key_path, key_pem)

        entry = IssuedCertificate(
            common_name=common_name,
            kind=kind,
            serial_number=serial_hex,
            cert_path=cert_rel,
            key_path=key_rel,
            not_valid_after=not_valid_after.astimezone(UTC).isoformat(),
            fingerprint=fingerprint,
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
                if existing.cert_path:
                    unlink_paths.append(existing.cert_path)
                if existing.key_path:
                    unlink_paths.append(existing.key_path)
                entries.append(
                    IssuedCertificate(
                        common_name=existing.common_name,
                        kind=existing.kind,
                        serial_number=existing.serial_number,
                        cert_path="",
                        key_path="",
                        not_valid_after=existing.not_valid_after,
                        fingerprint=existing.fingerprint,
                        revoked_at=when,
                    )
                )
            else:
                entries.append(existing)
        entries.append(entry)
        self._write_index(entries)
        for rel in unlink_paths:
            (self.root / rel).unlink(missing_ok=True)
        return entry

    def delete_certificate(self, identity: str, *, force: bool = False) -> IssuedCertificate:
        """Remove cert/key files from disk.

        Active (non-revoked) certificates require ``force=True`` and are removed
        from the index entirely. Revoked certificates become tombstones (serial
        retained for CRL generation; paths cleared).

        The index is rewritten before unlinking files so a mid-delete failure
        cannot leave the index pointing at missing paths.
        """
        entry = self.get_certificate(identity)
        if entry is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        if entry.revoked_at is None and not force:
            raise ValueError(f"Certificate {entry.common_name!r} is still active; revoke first or pass force=True")

        cert_rel = entry.cert_path
        key_rel = entry.key_path

        if entry.revoked_at is not None:
            tombstone = IssuedCertificate(
                common_name=entry.common_name,
                kind=entry.kind,
                serial_number=entry.serial_number,
                cert_path="",
                key_path="",
                not_valid_after=entry.not_valid_after,
                fingerprint=entry.fingerprint,
                revoked_at=entry.revoked_at,
            )
            remaining = [
                tombstone if (e.common_name == entry.common_name and e.serial_number == entry.serial_number) else e
                for e in self._read_index()
            ]
            self._write_index(remaining)
            if cert_rel:
                (self.root / cert_rel).unlink(missing_ok=True)
            if key_rel:
                (self.root / key_rel).unlink(missing_ok=True)
            return tombstone

        remaining = [
            e
            for e in self._read_index()
            if not (e.common_name == entry.common_name and e.serial_number == entry.serial_number)
        ]
        self._write_index(remaining)
        if cert_rel:
            (self.root / cert_rel).unlink(missing_ok=True)
        if key_rel:
            (self.root / key_rel).unlink(missing_ok=True)
        return entry

    def ensure_layout(self) -> None:
        """Create the store directory tree (does not write a CA).

        Migrates a legacy flat layout (``ca.crt`` / ``certs/`` at the root) when
        present.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        if self._is_legacy_layout():
            self._migrate_legacy_layout()
        self.ca_dir.mkdir(exist_ok=True)
        self.clients_dir.mkdir(exist_ok=True)
        self.servers_dir.mkdir(exist_ok=True)
        self.bundles_dir.mkdir(exist_ok=True)
        if not self.index_path.exists():
            if self.ca_cert_path.is_file() and self.ca_key_path.is_file():
                raise FileNotFoundError(f"Expected index.json under {self.ca_dir} (CA present but index missing)")
            self._write_index([])

    def get_certificate(self, identity: str) -> IssuedCertificate | None:
        """Lookup by common name or hex serial (case-insensitive; ``0x`` optional).

        When several entries match a common name, a live (non-revoked) entry wins
        so re-issue after revoke keeps resolving the current certificate.
        """
        needle = identity.strip()
        if not needle:
            return None
        candidates: list[IssuedCertificate] = []
        for entry in self._read_index():
            if not entry.cert_path:
                continue
            serial = entry.serial_number.lower()
            needle_l = needle.lower()
            if (
                entry.common_name.casefold() == needle.casefold()
                or serial == needle_l
                or serial == needle_l.removeprefix("0x")
            ):
                candidates.append(entry)
        if not candidates:
            return None
        for entry in candidates:
            if entry.revoked_at is None:
                return entry
        return candidates[0]

    def has_ca(self) -> bool:
        self._maybe_migrate_legacy_layout()
        return self.ca_cert_path.is_file() and self.ca_key_path.is_file()

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

    def mark_revoked(self, identity: str, *, revoked_at: datetime | None = None) -> IssuedCertificate:
        """Mark an issued cert revoked in the index.

        Idempotent: an already-revoked entry keeps its original ``revoked_at``.
        Identity resolution matches :meth:`get_certificate` (strip / ``0x`` serial).
        """
        target = self.get_certificate(identity)
        if target is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
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
                    found = IssuedCertificate(
                        common_name=entry.common_name,
                        kind=entry.kind,
                        serial_number=entry.serial_number,
                        cert_path=entry.cert_path,
                        key_path=entry.key_path,
                        not_valid_after=entry.not_valid_after,
                        fingerprint=entry.fingerprint,
                        revoked_at=when.isoformat(),
                    )
                    updated.append(found)
            else:
                updated.append(entry)
        if found is None:
            raise KeyError(f"Expected issued certificate matching {identity!r}")
        self._write_index(updated)
        return found

    def read_ca(self) -> tuple[bytes, bytes]:
        """Return ``(ca_cert_pem, ca_key_pem)``."""
        self._maybe_migrate_legacy_layout()
        if not self.ca_cert_path.is_file() or not self.ca_key_path.is_file():
            raise FileNotFoundError(f"Expected CA files under {self.ca_dir}")
        return self.ca_cert_path.read_bytes(), self.ca_key_path.read_bytes()

    def read_certificate_pem(self, entry: IssuedCertificate) -> bytes:
        if not entry.cert_path:
            raise FileNotFoundError(f"Expected on-disk certificate for {entry.common_name!r}")
        return self._path_under_root(entry.cert_path).read_bytes()

    def read_crl(self) -> bytes | None:
        self._maybe_migrate_legacy_layout()
        if not self.crl_path.is_file():
            return None
        return self.crl_path.read_bytes()

    def read_key_pem(self, entry: IssuedCertificate) -> bytes:
        if not entry.key_path:
            raise FileNotFoundError(f"Expected on-disk key for {entry.common_name!r}")
        return self._path_under_root(entry.key_path).read_bytes()

    def revoked_entries(self) -> list[tuple[int, datetime]]:
        """Return ``(serial_int, revoked_at)`` for CRL generation (includes tombstones)."""
        result: list[tuple[int, datetime]] = []
        for entry in self._read_index():
            if entry.revoked_at is None:
                continue
            result.append((int(entry.serial_number, 16), datetime.fromisoformat(entry.revoked_at)))
        return result

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
        path = self._path_under_root(rel)
        _write_secret(path, p12_bytes)
        return path

    def write_ca(self, cert_pem: bytes, key_pem: bytes, *, force: bool = False) -> None:
        """Persist the CA certificate and private key (key mode 0600).

        Refuses to overwrite an existing CA unless ``force=True``.
        """
        # Migrate first so legacy root CA material is visible to has_ca().
        self.ensure_layout()
        if self.has_ca() and not force:
            raise ValueError(f"CA already exists under {self.root}; pass force=True to replace")
        _write_plain(self._validated_write_path("ca/ca.crt"), cert_pem)
        _write_secret(self._validated_write_path("ca/ca.key"), key_pem)

    def write_crl(self, crl_pem: bytes) -> None:
        self.ensure_layout()
        _write_plain(self._validated_write_path("ca/crl.pem"), crl_pem)

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
            self._migrate_legacy_layout()

    def _migrate_legacy_layout(self) -> None:
        """Move flat-root CA material and ``certs/`` leaves into the typed tree.

        Order is re-entrant: rewrite leaves + index under ``ca/`` first, then move
        CA PEMs last so a mid-migration failure still leaves ``_is_legacy_layout``
        true and a later open can finish the job.
        """
        self.ca_dir.mkdir(exist_ok=True)
        self.clients_dir.mkdir(exist_ok=True)
        self.servers_dir.mkdir(exist_ok=True)
        self.bundles_dir.mkdir(exist_ok=True)

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
                    leaf_dir = "clients" if entry.kind == "client" else "servers"
                    new_cert = f"{leaf_dir}/{Path(cert_rel).name}"
                    new_key = f"{leaf_dir}/{Path(key_rel).name}" if key_rel else ""
                    if old_cert.is_file():
                        dest_cert = self._path_under_root(new_cert)
                        dest_cert.parent.mkdir(parents=True, exist_ok=True)
                        if not dest_cert.exists():
                            shutil.move(str(old_cert), str(dest_cert))
                    if old_key is not None and old_key.is_file() and new_key:
                        dest_key = self._path_under_root(new_key)
                        dest_key.parent.mkdir(parents=True, exist_ok=True)
                        if not dest_key.exists():
                            shutil.move(str(old_key), str(dest_key))
                    entry = IssuedCertificate(
                        common_name=entry.common_name,
                        kind=entry.kind,
                        serial_number=entry.serial_number,
                        cert_path=new_cert if cert_rel else "",
                        key_path=new_key if key_rel else "",
                        not_valid_after=entry.not_valid_after,
                        fingerprint=entry.fingerprint,
                        revoked_at=entry.revoked_at,
                    )
                elif cert_rel:
                    self._path_under_root(cert_rel)
                    if key_rel:
                        self._path_under_root(key_rel)
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
        """Resolve ``relative`` under the store root for a fresh write, refusing a symlink anywhere in it.

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
            if entry.cert_path:
                self._path_under_root(entry.cert_path)
            if entry.key_path:
                self._path_under_root(entry.key_path)
        return entries

    def _write_index(self, entries: list[IssuedCertificate]) -> None:
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        payload = [asdict(e) for e in entries]
        # _validated_write_path rejects a symlink at index.json.tmp itself
        # (wherever it points) and, via _path_under_root, one at ca/ that
        # would resolve outside the store root. index_path itself doesn't
        # need this: replace() below is a rename(2), which swaps the
        # destination directory entry rather than following a symlink there.
        tmp = self._validated_write_path("ca/index.json.tmp")
        _write_plain(tmp, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        tmp.replace(self.index_path)


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
    if kind not in ("client", "server"):
        raise ValueError(f"Expected kind 'client' or 'server', got {kind!r}")
    typed_kind: CertKind = kind
    revoked_raw = data.get("revoked_at")
    return IssuedCertificate(
        common_name=str(data["common_name"]),
        kind=typed_kind,
        serial_number=str(data["serial_number"]),
        cert_path=str(data["cert_path"]),
        key_path=str(data["key_path"]),
        not_valid_after=str(data["not_valid_after"]),
        fingerprint=str(data["fingerprint"]),
        revoked_at=None if revoked_raw is None else str(revoked_raw),
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


def _safe_filename(common_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in common_name.strip())
    if not cleaned:
        raise ValueError("Expected a common_name that yields a non-empty filename")
    return cleaned


# write_ca/write_crl/_write_index/_migrate_legacy_layout resolve their target
# through _validated_write_path before calling this, which rejects a symlink
# at the target itself (wherever it points) and, via _path_under_root, one at
# a parent component like "ca/" that would resolve outside the store root.
# This is the last-component backstop for the TOCTOU gap that check-then-open
# leaves open: a symlink planted at the same path between that check and this
# open() call. O_NOFOLLOW makes the open() itself fail (ELOOP) rather than
# write through such a link. Missing on Windows; there is no equivalent flag,
# so that race is not closed there.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _open_new_file(path: Path, *, mode: int) -> int:
    """Open ``path`` for a fresh write, refusing to follow a symlink already there."""
    if path.is_symlink():
        raise ValueError(f"Expected {path} to not already exist as a symlink")
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW, mode)


def _write_all(fd: int, data: bytes, *, path: Path) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(f"Expected progress writing {path}, got {written} bytes")
        view = view[written:]


def _write_plain(path: Path, data: bytes) -> None:
    """Write non-secret bytes (cert/CRL/index), refusing to follow a pre-planted symlink at ``path``."""
    fd = _open_new_file(path, mode=0o644)
    try:
        _write_all(fd, data, path=path)
    finally:
        os.close(fd)


def _write_secret(path: Path, data: bytes) -> None:
    """Write secret bytes with mode 0600 from creation (no world-readable window)."""
    fd = _open_new_file(path, mode=0o600)
    try:
        _write_all(fd, data, path=path)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
