"""The store publishes stapled OCSP responses, answers OCSP requests, and sets the OCSP URL (issue #160)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from hamcrest import assert_that, calling, contains_string, empty, equal_to, is_, raises
from pytest import CaptureFixture

from tiny_pki import TinyPkiError, generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import _HELD_LOCKS, CertificateStore, IssuedCertificate  # pyright: ignore[reportPrivateUsage]

_CA = generate_ca_certificate("Store OCSP CA", key_type="ec-p256")


def _cert(store: CertificateStore, name: str) -> x509.Certificate:
    entry = store.get_certificate(name)
    assert entry is not None
    return x509.load_pem_x509_certificate(store.read_certificate_pem(entry))


def _ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [str(d.access_location.value) for d in aia]


def _request(store: CertificateStore, cert: x509.Certificate) -> bytes:
    issuer = x509.load_pem_x509_certificate(store.read_ca_certificate())
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    return request.public_bytes(serialization.Encoding.DER)


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit) as exited:
            main(argv)
        assert_that(exited.value.code, equal_to(1))
    captured = capsys.readouterr()
    return captured.out, captured.err


def _status(path: Path) -> ocsp.OCSPCertStatus:
    return ocsp.load_der_ocsp_response(path.read_bytes()).certificate_status


def _store(tmp_path: Path, *, key_secret: str | None = None) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA, key_secret=key_secret)
    store.publish_crl(key_secret=key_secret)
    return store


def test_cli_ocsp_publish_url_and_disable(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", capsys=capsys)
    out, _ = _run(root, "ocsp", "url", capsys=capsys)
    assert_that(out, contains_string("no OCSP URL"))
    _run(root, "ocsp", "url", "http://ocsp.home/", capsys=capsys)
    assert_that(_run(root, "ocsp", "url", capsys=capsys)[0].strip(), equal_to("http://ocsp.home/"))
    _run(root, "create", "server", "api.home", "--san", "api.home", "--key-type", "ec-p256", capsys=capsys)
    store = CertificateStore(root)
    assert_that(_ocsp_urls(_cert(store, "api.home")), equal_to(["http://ocsp.home/"]))

    out, _ = _run(root, "ocsp", "--days", "3", capsys=capsys)
    assert_that(out, contains_string("published 1 OCSP response(s)"))
    assert_that(out, contains_string("valid 3 days"))
    listed = json.loads(_run(root, "list", "ca", "--json", capsys=capsys)[0])
    assert_that(
        (listed["ocsp_days"], listed["ocsp_url"], listed["ocsp_dir"]),
        equal_to((3, "http://ocsp.home/", str(store.ocsp_dir))),
    )
    out, _ = _run(root, "list", "ca", capsys=capsys)
    assert_that(out, contains_string("valid 3 days per publish"))

    _run(root, "ocsp", "url", "--clear", capsys=capsys)
    _run(root, "create", "server", "web.home", "--san", "web.home", "--key-type", "ec-p256", capsys=capsys)
    assert_that(_ocsp_urls(_cert(store, "web.home")), is_(empty()))
    assert_that(sorted(p.name for p in store.ocsp_dir.iterdir()), equal_to(["api.home.der", "web.home.der"]))

    out, _ = _run(root, "ocsp", "disable", capsys=capsys)
    assert_that(out, contains_string("OCSP stapling disabled"))
    assert_that(store.ocsp_dir.exists(), is_(False))
    assert_that(json.loads(_run(root, "list", "ca", "--json", capsys=capsys)[0])["ocsp_days"], is_(None))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("ocsp", "bogus"), "Expected ocsp publish|disable|url"),
        (("ocsp", "publish", "extra"), "Unexpected extra arguments"),
        (("ocsp", "url", "http://a.home/", "extra"), "Unexpected extra arguments"),
        (("ocsp", "--days", "0"), "Expected --days between 1 and 30"),
        (("ocsp", "--days", "31"), "Expected --days between 1 and 30"),
        (("ocsp", "--days", "x"), "Expected a whole number of days"),
        (("ocsp", "disable", "--days", "3"), "only supported for ocsp publish"),
        (("ocsp", "url", "--days", "3"), "only supported for ocsp publish"),
        (("ocsp", "--clear"), "--clear is only supported for ocsp url"),
        (("ocsp", "url", "http://a.home/", "--clear"), "not both"),
        (("ocsp", "url", "ftp://a.home/"), "Expected an http:// or https:// URL"),
    ],
)
def test_cli_ocsp_refuses_bad_invocations(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...], message: str
) -> None:
    root = tmp_path / "store"
    _run(root, "init", "--key-type", "ec-p256", capsys=capsys)
    _, err = _run(root, *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))
    assert_that(CertificateStore(root).ocsp_url, is_(None))
    assert_that(CertificateStore(root).ocsp_validity_days, is_(None))


def test_certificates_from_a_replaced_ca_do_not_block_crl_publishing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_server("old.home", ["old.home"], key_type="ec-p256")
    store.publish_ocsp()
    store.write_ca(*generate_ca_certificate("Replacement CA", key_type="ec-p256"), force=True)
    store.issue_server("new.home", ["new.home"], key_type="ec-p256")
    store.publish_crl()
    assert_that(sorted(p.name for p in store.ocsp_dir.iterdir()), equal_to(["new.home.der"]))
    store.revoke("new.home")
    assert_that(_status(store.ocsp_dir / "new.home.der"), equal_to(ocsp.OCSPCertStatus.REVOKED))


def test_every_crl_publish_refreshes_the_responses_until_disabled(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.issue_client("alice", key_type="ec-p256")
    written = store.publish_ocsp()
    assert_that([p.name for p in written], equal_to(["api.home.der"]))
    response = store.ocsp_dir / "api.home.der"
    assert_that(_status(response), equal_to(ocsp.OCSPCertStatus.GOOD))
    assert_that(store.ocsp_validity_days, equal_to(7))

    first = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    assert_that(
        ocsp.load_der_ocsp_response(response.read_bytes()).serial_number, equal_to(int(first.serial_number, 16))
    )
    store.revoke("api.home")
    assert_that(_status(response), equal_to(ocsp.OCSPCertStatus.REVOKED))
    store.delete("api.home")
    assert_that(list(store.ocsp_dir.iterdir()), is_(empty()))

    store.issue_server("web.home", ["web.home"], key_type="ec-p256")
    assert_that([p.name for p in store.ocsp_dir.iterdir()], equal_to(["web.home.der"]))
    store.disable_ocsp()
    store.issue_server("db.home", ["db.home"], key_type="ec-p256")
    store.publish_crl()
    assert_that(store.ocsp_dir.exists(), is_(False))


def test_live_certificate_keeps_the_stable_name_next_to_a_revoked_one(tmp_path: Path) -> None:
    store = _store(tmp_path)
    old = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.revoke("api.home")
    new = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.issue_server("api home", ["api.home"], key_type="ec-p256", include_common_name_in_sans=False)
    store.publish_ocsp()
    names = sorted(p.name for p in store.ocsp_dir.iterdir())
    assert_that(names, equal_to(sorted(["api.home.der", f"api.home-{old.serial_number}.der", "api_home.der"])))
    stable = ocsp.load_der_ocsp_response((store.ocsp_dir / "api.home.der").read_bytes())
    assert_that(
        (stable.serial_number, stable.certificate_status),
        equal_to((int(new.serial_number, 16), ocsp.OCSPCertStatus.GOOD)),
    )
    assert_that(_status(store.ocsp_dir / f"api.home-{old.serial_number}.der"), equal_to(ocsp.OCSPCertStatus.REVOKED))


def test_newest_revoked_certificate_keeps_the_stable_name(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.publish_ocsp()
    old = store.issue_server("web1", ["web1.home"], key_type="ec-p256")
    store.revoke(f"0x{old.serial_number}")
    new = store.issue_server("web1", ["web1.home"], key_type="ec-p256")
    store.revoke(f"0x{new.serial_number}")
    names = sorted(p.name for p in store.ocsp_dir.iterdir())
    assert_that(names, equal_to(sorted(["web1.der", f"web1-{old.serial_number}.der"])))
    stable = ocsp.load_der_ocsp_response((store.ocsp_dir / "web1.der").read_bytes())
    assert_that(
        (stable.serial_number, stable.certificate_status),
        equal_to((int(new.serial_number, 16), ocsp.OCSPCertStatus.REVOKED)),
    )


def test_common_names_sharing_a_file_name_never_get_the_stable_name(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.publish_ocsp()
    live = store.issue_server("web_home", ["web.home"], key_type="ec-p256", include_common_name_in_sans=False)
    other = store.issue_server("web!home", ["other.home"], key_type="ec-p256", include_common_name_in_sans=False)
    store.revoke(f"0x{other.serial_number}")
    names = sorted(p.name for p in store.ocsp_dir.iterdir())
    assert_that(
        names,
        equal_to(sorted([f"web_home-{live.serial_number}.der", f"web_home-{other.serial_number}.der"])),
    )


def test_writes_refresh_only_the_changed_server_responses(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.publish_ocsp()
    response = store.ocsp_dir / "api.home.der"
    before = response.read_bytes()
    store.issue_client("alice", key_type="ec-p256")
    store.revoke("alice")
    store.issue_server("web.home", ["web.home"], key_type="ec-p256")
    store.revoke("web.home")
    assert_that(response.read_bytes(), equal_to(before))
    assert_that(_status(store.ocsp_dir / "web.home.der"), equal_to(ocsp.OCSPCertStatus.REVOKED))
    store.publish_crl()
    assert_that(response.read_bytes() == before, is_(False))


def test_disable_ocsp_leaves_foreign_files_alone(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.publish_ocsp()
    stray = store.ocsp_dir / ".DS_Store"
    stray.write_bytes(b"fake")
    store.disable_ocsp()
    assert_that(store.ocsp_validity_days, is_(None))
    assert_that([p.name for p in store.ocsp_dir.iterdir()], equal_to([".DS_Store"]))


def test_ocsp_directory_is_key_free_and_world_readable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.publish_ocsp(validity_days=2)
    assert_that(stat.S_IMODE(store.ocsp_dir.stat().st_mode), equal_to(0o755))
    assert_that(stat.S_IMODE((store.ocsp_dir / "api.home.der").stat().st_mode), equal_to(0o644))
    assert_that(store.ocsp_validity_days, equal_to(2))
    assert_that(calling(store.publish_ocsp).with_args(validity_days=31), raises(TinyPkiError, "between 1 and 30"))
    assert_that(store.ocsp_validity_days, equal_to(2))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_openssl_accepts_the_stapled_response(tmp_path: Path) -> None:
    store = _store(tmp_path)
    entry = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.publish_ocsp()
    ca = str(store.public_dir / "ca.crt")
    command = [
        "openssl", "ocsp", "-respin", str(store.ocsp_dir / "api.home.der"),
        "-issuer", ca, "-CAfile", ca, "-cert", str(store.root / entry.cert_path),
    ]  # fmt: skip
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert_that(result.stderr + result.stdout, contains_string("Response verify OK"))
    assert_that(result.stdout, contains_string(": good"))


def test_respond_ocsp_reads_the_index_once_under_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    request = _request(store, _cert(store, "api.home"))
    reads: list[bool] = []
    read_index = CertificateStore._read_index  # pyright: ignore[reportPrivateUsage]

    def recording_read(self: CertificateStore) -> list[IssuedCertificate]:
        depth: dict[Path, int] = _HELD_LOCKS.__dict__.get("depth", {})
        reads.append(depth.get(self.lock_path, 0) > 0)
        return read_index(self)

    monkeypatch.setattr(CertificateStore, "_read_index", recording_read)
    store.respond_ocsp(request)
    assert_that(reads, equal_to([True]))


def test_respond_ocsp_answers_from_the_index(tmp_path: Path) -> None:
    store = _store(tmp_path)
    live = store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.issue_client("alice", key_type="ec-p256")
    alice = _cert(store, "alice")
    store.revoke("alice")
    store.delete("alice")
    good = ocsp.load_der_ocsp_response(store.respond_ocsp(_request(store, _cert(store, "api.home"))))
    assert_that(good.certificate_status, equal_to(ocsp.OCSPCertStatus.GOOD))
    assert_that(good.serial_number, equal_to(int(live.serial_number, 16)))
    revoked = ocsp.load_der_ocsp_response(store.respond_ocsp(_request(store, alice)))
    assert_that(revoked.certificate_status, equal_to(ocsp.OCSPCertStatus.REVOKED))

    other = CertificateStore(tmp_path / "other")
    other.write_ca(*generate_ca_certificate("Other CA", key_type="ec-p256"))
    other.publish_crl()
    stranger = x509.load_pem_x509_certificate(
        other.read_certificate_pem(other.issue_server("api.home", ["api.home"], key_type="ec-p256"))
    )
    request = ocsp.OCSPRequestBuilder().add_certificate_by_hash(
        good.issuer_name_hash, good.issuer_key_hash, stranger.serial_number, hashes.SHA1()
    )
    unknown = ocsp.load_der_ocsp_response(store.respond_ocsp(request.build().public_bytes(serialization.Encoding.DER)))
    assert_that(unknown.certificate_status, equal_to(ocsp.OCSPCertStatus.UNKNOWN))


def test_set_ocsp_url_applies_to_every_later_leaf(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = store.issue_client("before", key_type="ec-p256")
    store.set_ocsp_url(" https://pki.home/ocsp ")
    assert_that(store.ocsp_url, equal_to("https://pki.home/ocsp"))
    store.issue_client("alice", key_type="ec-p256")
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    for name in ("alice", "api.home"):
        assert_that(_ocsp_urls(_cert(store, name)), equal_to(["https://pki.home/ocsp"]))
    assert_that(_ocsp_urls(_cert(store, before.common_name)), is_(empty()))
    assert_that(calling(store.set_ocsp_url).with_args("mailto:ops@home"), raises(TinyPkiError, "http://"))
    store.set_ocsp_url(None)
    assert_that(store.ocsp_url, is_(None))
    store.set_ocsp_url(None)


def test_stapling_with_an_encrypted_ca_needs_the_secret(tmp_path: Path) -> None:
    secret = "s" * 32
    store = _store(tmp_path, key_secret=secret)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256", key_secret=secret)
    assert_that(calling(store.publish_ocsp), raises(TinyPkiError, "encrypted"))
    assert_that(store.ocsp_validity_days, is_(None))
    store.publish_ocsp(key_secret=secret)
    store.revoke("api.home", key_secret=secret)
    assert_that(_status(store.ocsp_dir / "api.home.der"), equal_to(ocsp.OCSPCertStatus.REVOKED))
