"""Stores sign intermediate CAs and run as one, with the chain and its CRLs published (issue #161)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    empty,
    equal_to,
    has_item,
    has_length,
    is_,
    none,
    not_,
    raises,
)
from pytest import CaptureFixture

from tiny_pki import TinyPkiError, generate_ca_certificate, generate_intermediate_ca_certificate
from tiny_pki.check import Status
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, check_store

_ROOT = generate_ca_certificate("Store Root", key_type="ec-p256", path_length=1)
_OTHER_ROOT = generate_ca_certificate("Other Root", key_type="ec-p256", path_length=1)
_ROOT_SECRET = "fake-root-secret-for-tests-only-0001"
_INT_SECRET = "fake-issuing-secret-for-tests-only-01"


def _crl_count(data: bytes) -> int:
    return data.count(b"-----BEGIN X509 CRL-----")


def _csr(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _pair(tmp_path: Path) -> tuple[CertificateStore, CertificateStore]:
    root = _root(tmp_path)
    intermediate = CertificateStore(tmp_path / "issuing")
    intermediate.init_intermediate(root, "Issuing CA", key_type="ec-p256")
    return root, intermediate


def _root(tmp_path: Path) -> CertificateStore:
    root = CertificateStore(tmp_path / "root")
    root.write_ca(*_ROOT)
    root.publish_crl()
    return root


def _rows(store: CertificateStore) -> dict[str, Status]:
    return {name: result.status for name, result in check_store(store)}


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


def test_init_intermediate_writes_chain_and_crls(tmp_path: Path) -> None:
    root, intermediate = _pair(tmp_path)
    entries = root.list_certificates(kind="intermediate")
    assert_that(entries, has_length(1))
    assert_that(entries[0].key_path, equal_to(""))
    assert_that(entries[0].cert_path, contains_string("intermediates/"))
    assert_that(list(root.intermediates_dir.iterdir()), has_length(1))
    assert_that(intermediate.ca_chain_path.read_bytes(), equal_to(_ROOT[0]))
    public = intermediate.public_dir
    assert_that((public / "ca-chain.pem").read_bytes(), equal_to(intermediate.read_ca_certificate() + _ROOT[0]))
    assert_that(_crl_count((public / "crl.pem").read_bytes()), equal_to(2))
    assert_that(_crl_count(intermediate.crl_path.read_bytes()), equal_to(1))
    assert_that(intermediate.read_chain_crls(), equal_to([root.read_crl()]))
    assert_that(set(_rows(intermediate).values()), equal_to({Status.OK}))
    assert_that(_rows(root)["Issuing CA"], is_(Status.OK))


def test_init_intermediate_checks_its_inputs_before_the_issuer_signs(tmp_path: Path) -> None:
    root = _root(tmp_path)
    intermediate = CertificateStore(tmp_path / "issuing")
    assert_that(
        calling(intermediate.init_intermediate).with_args(root, "Issuing CA", key_type="ec-p256", key_secret="short"),
        raises(TinyPkiError, "at least"),
    )
    assert_that(
        calling(intermediate.init_intermediate).with_args(root, "Issuing CA", key_type="ec-p256", crl_validity_days=0),
        raises(ValueError),
    )
    assert_that(root.list_certificates(kind="intermediate", status="all"), empty())
    assert_that(intermediate.has_ca(), is_(False))


def test_init_intermediate_revokes_the_new_certificate_when_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    intermediate = CertificateStore(tmp_path / "issuing")

    def fail_publish(*_args: object, **_kwargs: object) -> bytes:
        raise OSError("disk full")

    monkeypatch.setattr(intermediate, "publish_crl", fail_publish)
    assert_that(
        calling(intermediate.init_intermediate).with_args(root, "Issuing CA", key_type="ec-p256"),
        raises(OSError, "disk full"),
    )
    entries = root.list_certificates(kind="intermediate", status="all")
    assert_that(entries, has_length(1))
    assert_that(entries[0].revoked_at, not_(none()))
    assert_that(root.list_certificates(kind="intermediate", status="active"), empty())
    assert_that(intermediate.has_ca(), is_(False))
    assert_that(intermediate.ca_chain_path.exists(), is_(False))
    assert_that(sorted(path.name for path in intermediate.public_dir.iterdir()), empty())
    monkeypatch.undo()
    intermediate.init_intermediate(root, "Issuing CA", key_type="ec-p256")
    assert_that(root.list_certificates(kind="intermediate", status="active"), has_length(1))
    assert_that(set(_rows(intermediate).values()), equal_to({Status.OK}))


def test_root_store_has_no_chain(tmp_path: Path) -> None:
    root = _root(tmp_path)
    assert_that(root.read_ca_chain(), equal_to(_ROOT[0]))
    assert_that(root.read_chain_crls(), empty())
    assert_that((root.public_dir / "ca-chain.pem").exists(), is_(False))
    assert_that(
        calling(root.import_chain_crl).with_args(root.read_crl()),
        raises(TinyPkiError, "a root CA has no chain CRLs"),
    )


def test_renewing_an_intermediate_keeps_the_previous_one_live(tmp_path: Path) -> None:
    root, _ = _pair(tmp_path)
    root.issue_intermediate("Issuing CA", key_type="ec-p256")
    live = root.list_certificates(kind="intermediate", status="active")
    assert_that(live, has_length(2))
    assert_that(root.revoked_entries(), empty())


def test_intermediate_and_leaf_cannot_share_a_common_name(tmp_path: Path) -> None:
    root, _ = _pair(tmp_path)
    assert_that(
        calling(root.issue_client).with_args("Issuing CA", key_type="ec-p256"),
        raises(ValueError, "either an intermediate CA or a leaf"),
    )
    root.issue_client("alice", key_type="ec-p256")
    assert_that(
        calling(root.issue_intermediate).with_args("alice", key_type="ec-p256"),
        raises(ValueError, "either an intermediate CA or a leaf"),
    )


def test_intermediate_entries_never_take_a_key(tmp_path: Path) -> None:
    root = _root(tmp_path)
    cert_pem, key_pem = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    assert_that(
        calling(root.add_certificate).with_args(
            common_name="Issuing CA",
            kind="intermediate",
            serial_number=x509.load_pem_x509_certificate(cert_pem).serial_number,
            cert_pem=cert_pem,
            key_pem=key_pem,
            not_valid_after=x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc,
            fingerprint="f",
        ),
        raises(ValueError, "its key belongs in its own store"),
    )


def test_index_refuses_an_intermediate_key_path(tmp_path: Path) -> None:
    root, _ = _pair(tmp_path)
    index = json.loads(root.index_path.read_text())
    index[0]["key_path"] = index[0]["cert_path"].removesuffix(".crt") + ".key"
    root.index_path.write_text(json.dumps(index))
    assert_that(calling(root.list_certificates), raises(ValueError, "Expected no key path for intermediate CA"))


def test_import_chain_crl_replaces_and_refuses_rollback_or_strangers(tmp_path: Path) -> None:
    root, intermediate = _pair(tmp_path)
    old_crl = root.read_crl()
    assert old_crl is not None
    root.issue_client("alice", key_type="ec-p256")
    root.revoke("alice")
    new_crl = root.read_crl()
    assert new_crl is not None
    intermediate.import_chain_crl(new_crl)
    assert_that(intermediate.read_chain_crls(), equal_to([new_crl]))
    assert_that(_crl_count((intermediate.public_dir / "crl.pem").read_bytes()), equal_to(2))
    assert_that(
        calling(intermediate.import_chain_crl).with_args(old_crl),
        raises(TinyPkiError, "refusing to roll it back"),
    )
    stranger = CertificateStore(tmp_path / "stranger")
    stranger.write_ca(*_OTHER_ROOT)
    assert_that(
        calling(intermediate.import_chain_crl).with_args(stranger.publish_crl()),
        raises(TinyPkiError, "signed by a CA in this store's chain"),
    )
    assert_that(
        calling(intermediate.import_chain_crl).with_args(b"not a crl"),
        raises(TinyPkiError, "Expected a PEM CRL"),
    )


def test_write_ca_validates_the_chain(tmp_path: Path) -> None:
    cert_pem, key_pem = generate_intermediate_ca_certificate(*_ROOT, "Issuing CA", key_type="ec-p256")
    store = CertificateStore(tmp_path / "issuing")
    assert_that(
        calling(store.write_ca).with_args(cert_pem, key_pem, chain_pem=_OTHER_ROOT[0]),
        raises(TinyPkiError, "to be issued by the next chain certificate"),
    )
    assert_that(store.has_ca(), is_(False))
    store.write_ca(cert_pem, key_pem, chain_pem=_ROOT[0])
    assert_that(store.read_ca_chain(), equal_to(cert_pem + _ROOT[0]))
    store.write_ca(*_OTHER_ROOT, force=True)
    assert_that(store.ca_chain_path.exists(), is_(False))
    assert_that((store.public_dir / "ca-chain.pem").exists(), is_(False))


def _ca_usage(*, key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _signed_chain(
    *,
    root_path_length: int | None = 1,
    root_key_cert_sign: bool = True,
    root_constraints: x509.NameConstraints | None = None,
    intermediate_constraints: x509.NameConstraints | None = None,
) -> tuple[bytes, bytes, bytes]:
    """A correctly signed (intermediate cert, intermediate key, root cert) whose root may not authorize it."""
    now = datetime.now(UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hand Root")])
    root_builder = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=root_path_length), critical=True)
        .add_extension(_ca_usage(key_cert_sign=root_key_cert_sign), critical=True)
    )
    if root_constraints is not None:
        root_builder = root_builder.add_extension(root_constraints, critical=True)
    root_cert = root_builder.sign(root_key, hashes.SHA256())
    int_key = ec.generate_private_key(ec.SECP256R1())
    int_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hand Issuing")]))
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_usage(key_cert_sign=True), critical=True)
    )
    if intermediate_constraints is not None:
        int_builder = int_builder.add_extension(intermediate_constraints, critical=True)
    int_cert = int_builder.sign(root_key, hashes.SHA256())
    int_key_pem = int_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pem = serialization.Encoding.PEM
    return int_cert.public_bytes(pem), int_key_pem, root_cert.public_bytes(pem)


@pytest.mark.parametrize(
    ("root_path_length", "root_key_cert_sign", "reason"),
    [
        (0, True, "path_length=0 allows fewer than the 1 CA certificate"),
        (None, False, "Key Usage does not allow keyCertSign"),
    ],
)
def test_write_ca_refuses_a_signed_chain_the_root_does_not_authorize(
    tmp_path: Path, root_path_length: int | None, root_key_cert_sign: bool, reason: str
) -> None:
    cert_pem, key_pem, root_pem = _signed_chain(
        root_path_length=root_path_length, root_key_cert_sign=root_key_cert_sign
    )
    store = CertificateStore(tmp_path / "issuing")
    assert_that(
        calling(store.write_ca).with_args(cert_pem, key_pem, chain_pem=root_pem),
        raises(TinyPkiError, reason),
    )
    assert_that(store.has_ca(), is_(False))
    allowed_pem, allowed_key, allowed_root = _signed_chain(root_path_length=1, root_key_cert_sign=True)
    store.write_ca(allowed_pem, allowed_key, chain_pem=allowed_root)
    assert_that(store.read_ca_chain(), equal_to(allowed_pem + allowed_root))


def _dns(*names: str) -> list[x509.GeneralName]:
    return [x509.DNSName(name) for name in names]


@pytest.mark.parametrize(
    ("root_constraints", "intermediate_constraints", "reason"),
    [
        (x509.NameConstraints(_dns("allowed.example"), None), None, "to permit only names within"),
        (
            x509.NameConstraints(_dns("allowed.example"), None),
            x509.NameConstraints(_dns("example"), None),
            "to permit only names within",
        ),
        (x509.NameConstraints(None, _dns("bad.example")), None, "to exclude 'bad.example'"),
    ],
)
def test_write_ca_refuses_an_intermediate_broader_than_its_root(
    tmp_path: Path,
    root_constraints: x509.NameConstraints,
    intermediate_constraints: x509.NameConstraints | None,
    reason: str,
) -> None:
    cert_pem, key_pem, root_pem = _signed_chain(
        root_constraints=root_constraints, intermediate_constraints=intermediate_constraints
    )
    store = CertificateStore(tmp_path / "issuing")
    assert_that(
        calling(store.write_ca).with_args(cert_pem, key_pem, chain_pem=root_pem),
        raises(TinyPkiError, reason),
    )
    assert_that(store.has_ca(), is_(False))


@pytest.mark.parametrize(
    ("root_constraints", "intermediate_constraints", "inside", "outside"),
    [
        (
            x509.NameConstraints(_dns("allowed.example"), None),
            x509.NameConstraints(_dns("api.allowed.example"), None),
            "api.allowed.example",
            "outside.example",
        ),
        (
            x509.NameConstraints(None, _dns("bad.example")),
            x509.NameConstraints(None, _dns("example")),
            "host.test",
            "www.bad.example",
        ),
        (
            x509.NameConstraints(None, _dns("bad.example")),
            x509.NameConstraints(_dns("good.example"), None),
            "www.good.example",
            "www.bad.example",
        ),
    ],
)
def test_write_ca_accepts_an_intermediate_within_its_root_and_issues_only_inside(
    tmp_path: Path,
    root_constraints: x509.NameConstraints,
    intermediate_constraints: x509.NameConstraints,
    inside: str,
    outside: str,
) -> None:
    cert_pem, key_pem, root_pem = _signed_chain(
        root_constraints=root_constraints, intermediate_constraints=intermediate_constraints
    )
    store = CertificateStore(tmp_path / "issuing")
    store.write_ca(cert_pem, key_pem, chain_pem=root_pem)
    store.issue_server(inside, [inside], key_type="ec-p256", validity_days=5)
    assert_that(
        calling(store.issue_server).with_args(outside, [outside], key_type="ec-p256", validity_days=5),
        raises(TinyPkiError),
    )


def test_check_flags_a_missing_chain_crl_and_a_revoked_intermediate(tmp_path: Path) -> None:
    root, intermediate = _pair(tmp_path)
    intermediate.chain_crl_path.unlink()
    rows = _rows(intermediate)
    assert_that(rows["issuer crl Store Root"], is_(Status.UNTRUSTED))
    root.revoke("Issuing CA")
    root_crl = root.read_crl()
    assert root_crl is not None
    intermediate.import_chain_crl(root_crl)
    rows = _rows(intermediate)
    assert_that(rows["ca"], is_(Status.REVOKED))
    assert_that(rows["issuer crl Store Root"], is_(Status.OK))
    assert_that(rows["issuer Store Root"], is_(Status.OK))


def test_encrypted_stores_on_both_sides(tmp_path: Path) -> None:
    root = CertificateStore(tmp_path / "root")
    root.write_ca(*_ROOT, key_secret=_ROOT_SECRET)
    root.publish_crl(key_secret=_ROOT_SECRET)
    intermediate = CertificateStore(tmp_path / "issuing")
    assert_that(
        calling(intermediate.init_intermediate).with_args(root, "Issuing CA", key_type="ec-p256"),
        raises(TinyPkiError, "provide a key secret"),
    )
    intermediate.init_intermediate(
        root, "Issuing CA", key_type="ec-p256", key_secret=_INT_SECRET, issuer_key_secret=_ROOT_SECRET
    )
    assert_that(intermediate.ca_key_encrypted, is_(True))
    assert_that(intermediate.list_certificates(), empty())


def test_cli_root_intermediate_leaf_workflow(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root_dir, int_dir = tmp_path / "root", tmp_path / "issuing"
    out, _ = _run(root_dir, "init", "--cn", "CLI Root", "--path-length", "1", "--key-type", "ec-p256", capsys=capsys)
    assert_that(out, contains_string("it may sign intermediate CAs"))
    out, _ = _run(
        int_dir,
        "init",
        "--intermediate-of",
        str(root_dir),
        "--cn",
        "CLI Issuing",
        "--permit",
        "home.arpa",
        "--key-type",
        "ec-p256",
        capsys=capsys,
    )
    assert_that(out, contains_string("intermediate CA created: CLI Issuing"))
    _run(int_dir, "create", "server", "nas.home.arpa", "--key-type", "ec-p256", capsys=capsys)
    _run(int_dir, "create", "client", "alice", "--key-type", "ec-p256", capsys=capsys)

    out, _ = _run(root_dir, "list", "intermediates", "--json", capsys=capsys)
    rows = json.loads(out)
    assert_that(
        [(row["cn"], row["kind"], row["key_path"]) for row in rows], equal_to([("CLI Issuing", "intermediate", "")])
    )
    out, _ = _run(root_dir, "list", "--json", capsys=capsys)
    assert_that(json.loads(out)["intermediates"], equal_to(1))
    out, _ = _run(int_dir, "list", "ca", "--json", capsys=capsys)
    ca = json.loads(out)
    assert_that((ca["chain"], ca["chain_path"]), equal_to((["CLI Root"], str(int_dir.resolve() / "ca" / "chain.pem"))))
    out, _ = _run(int_dir, "list", "ca", capsys=capsys)
    assert_that(out, contains_string("issued by CLI Root"))

    p12_path = tmp_path / "alice.p12"
    password_file = tmp_path / "password"
    password_file.write_text("fake-test-password-123\n")
    _run(
        int_dir, "export", "p12", "alice", "--out", str(p12_path), "--password-file", str(password_file), capsys=capsys
    )
    bundle = pkcs12.load_pkcs12(p12_path.read_bytes(), b"fake-test-password-123")
    subjects = [cert.certificate.subject.rfc4514_string() for cert in bundle.additional_certs]
    assert_that(subjects, equal_to(["O=tiny-pki,CN=CLI Issuing", "O=tiny-pki,CN=CLI Root"]))
    _, err = _run(root_dir, "export", "p12", "CLI Issuing", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("is an intermediate CA whose key lives in its own store"))

    _run(root_dir, "revoke", "CLI Issuing", capsys=capsys)
    out, _ = _run(int_dir, "crl", "--chain-crl", str(root_dir / "public" / "crl.pem"), capsys=capsys)
    assert_that(out, contains_string("imported 1 issuer CRL(s)"))
    with pytest.raises(SystemExit) as exited:
        main(["--store", str(int_dir), "--color", "never", "check", "--kind", "ca"])
    assert_that(exited.value.code, equal_to(2))
    assert_that(capsys.readouterr().out, contains_string("revoked"))


def test_cli_sign_intermediate_from_csr(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = _root(tmp_path)
    csr_path = tmp_path / "bao.csr"
    csr_path.write_bytes(_csr("bao"))
    out_path = tmp_path / "bao.crt"
    out, _ = _run(
        root.root,
        "sign",
        "intermediate",
        "OpenBao Issuing",
        "--csr",
        str(csr_path),
        "--permit",
        "svc.example",
        "--days",
        "365",
        "--out",
        str(out_path),
        capsys=capsys,
    )
    assert_that(out, contains_string("the private key stays on the intermediate CA"))
    cert = x509.load_pem_x509_certificate(out_path.read_bytes())
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert_that((constraints.ca, constraints.path_length), equal_to((True, 0)))
    entry = root.get_certificate("OpenBao Issuing")
    assert entry is not None
    assert_that(entry.kind, equal_to("intermediate"))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (["sign", "intermediate", "X", "--csr", "c.csr", "--san", "x.example"], "do not apply to intermediate CAs"),
        (["sign", "intermediate", "X", "--csr", "c.csr", "--keep-previous"], "do not apply to intermediate CAs"),
        (["sign", "client", "X", "--csr", "c.csr", "--permit", "x.example"], "--permit-uri are only supported"),
        (["init", "--issuer-key-secret-file", "s"], "--issuer-key-secret-file requires --intermediate-of"),
        (["init", "--path-length", "2"], "Expected --path-length 0"),
    ],
)
def test_cli_rejects_misplaced_flags(
    tmp_path: Path, capsys: CaptureFixture[str], words: list[str], message: str
) -> None:
    _, err = _run(tmp_path / "store", *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))


def test_cli_init_intermediate_rejects_path_length_and_missing_issuer(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _, err = _run(
        tmp_path / "issuing",
        "init",
        "--intermediate-of",
        str(root.root),
        "--path-length",
        "1",
        capsys=capsys,
        expect_ok=False,
    )
    assert_that(err, contains_string("an intermediate CA always signs leaves only"))
    _, err = _run(
        tmp_path / "issuing", "init", "--intermediate-of", str(tmp_path / "nowhere"), capsys=capsys, expect_ok=False
    )
    assert_that(err, contains_string("Expected a CA under --intermediate-of"))
    assert_that((tmp_path / "issuing" / "ca" / "ca.crt").exists(), is_(False))


def test_cli_issuer_key_secret_file(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = CertificateStore(tmp_path / "root")
    root.write_ca(*_ROOT, key_secret=_ROOT_SECRET)
    root.publish_crl(key_secret=_ROOT_SECRET)
    secret_file = tmp_path / "root-secret"
    secret_file.write_text(_ROOT_SECRET + "\n")
    secret_file.chmod(0o600)
    _run(
        tmp_path / "issuing",
        "init",
        "--intermediate-of",
        str(root.root),
        "--issuer-key-secret-file",
        str(secret_file),
        "--key-type",
        "ec-p256",
        capsys=capsys,
    )
    assert_that(CertificateStore(tmp_path / "issuing").has_ca(), is_(True))
    plain_root = _root(tmp_path / "plain")
    _, err = _run(
        tmp_path / "issuing2",
        "init",
        "--intermediate-of",
        str(plain_root.root),
        "--issuer-key-secret-file",
        str(secret_file),
        capsys=capsys,
        expect_ok=False,
    )
    assert_that(err, contains_string("the issuer's CA private key is not encrypted"))


def test_list_ca_text_for_a_root_mentions_no_chain(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = _root(tmp_path)
    out, _ = _run(root.root, "list", "ca", "--json", capsys=capsys)
    ca = json.loads(out)
    assert_that(ca["chain_path"], is_(none()))
    assert_that(ca["chain"], empty())
    out, _ = _run(root.root, "list", "ca", capsys=capsys)
    assert_that(out, not_(contains_string("chain ")))
    assert_that(out.splitlines(), has_item(contains_string("ca.crt + crl.pem for TLS servers")))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_checks_every_crl_in_the_published_chain(tmp_path: Path) -> None:
    root, intermediate = _pair(tmp_path)
    entry = intermediate.issue_server("nas.example", ["nas.example"], key_type="ec-p256")
    leaf = tmp_path / "leaf.pem"
    leaf.write_bytes(intermediate.read_certificate_pem(entry))
    command = [
        "openssl",
        "verify",
        "-crl_check_all",
        "-CAfile",
        str(root.public_dir / "ca.crt"),
        "-untrusted",
        str(intermediate.public_dir / "ca.crt"),
        "-CRLfile",
        str(intermediate.public_dir / "crl.pem"),
        str(leaf),
    ]
    assert_that(subprocess.run(command, capture_output=True, check=False).returncode, equal_to(0))
    root.revoke("Issuing CA")
    root_crl = root.read_crl()
    assert root_crl is not None
    intermediate.import_chain_crl(root_crl)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert_that(result.returncode, not_(equal_to(0)))
    assert_that(result.stdout + result.stderr, contains_string("certificate revoked"))
