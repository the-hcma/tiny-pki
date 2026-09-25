"""`tiny-pki check PATH...`: chain, DER, CRL, directory, and PKCS#12 targets (issue #48)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from hamcrest import assert_that, contains_string, equal_to, has_length, is_not
from pytest import CaptureFixture

from tiny_pki import (
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
)
from tiny_pki.cli.main import main


def test_chain_file_checks_every_certificate(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    chain = tmp_path / "chain.pem"
    chain.write_bytes(_SERVER_CERT + _CA_CERT)
    assert_that(_check(chain), equal_to(0))
    out = capsys.readouterr().out
    assert_that(out, contains_string(f"{chain} #1"))
    assert_that(out, contains_string(f"{chain} #2"))
    assert_that(out, contains_string("check: 2 ok"))
    assert_that(_check(chain, "--within", "100"), equal_to(1))
    assert_that(capsys.readouterr().out, contains_string("check: 1 expiring, 1 ok"))


def test_key_and_certificate_pem_checks_only_the_certificate(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    combined = tmp_path / "server.pem"
    combined.write_bytes(_SERVER_KEY + _SERVER_CERT)
    assert_that(_check(combined, "--json"), equal_to(0))
    results = json.loads(capsys.readouterr().out)["results"]
    assert_that(results, has_length(1))
    assert_that(results[0]["name"], equal_to(str(combined)))
    assert_that(results[0]["kind"], equal_to("server"))


def test_der_certificate_and_crl(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    der_cert = tmp_path / "server.cer"
    der_cert.write_bytes(x509.load_pem_x509_certificate(_SERVER_CERT).public_bytes(serialization.Encoding.DER))
    der_crl = tmp_path / "ca.crl"
    der_crl.write_bytes(x509.load_pem_x509_crl(_CRL).public_bytes(serialization.Encoding.DER))
    assert_that(_check(der_cert, der_crl, "--json"), equal_to(0))
    results = json.loads(capsys.readouterr().out)["results"]
    assert_that(sorted(r["kind"] for r in results), equal_to(["crl", "server"]))


def test_directory_scan_skips_non_certificates(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    (tmp_path / "ca.crt").write_bytes(_CA_CERT)
    (tmp_path / "crl.pem").write_bytes(_CRL)
    (tmp_path / "server.pem").write_bytes(_SERVER_CERT)
    (tmp_path / "server-key.pem").write_bytes(_SERVER_KEY)
    (tmp_path / "bundle.p12").write_bytes(_P12)
    (tmp_path / "README.txt").write_text("not scanned")
    assert_that(_check(tmp_path, "--ca", str(tmp_path / "ca.crt")), equal_to(0))
    captured = capsys.readouterr()
    assert_that(captured.out, contains_string("check: 3 ok"))
    assert_that(captured.err, contains_string("skipped"))
    assert_that(captured.err, contains_string("server-key.pem: Expected a certificate or CRL"))
    assert_that(captured.err, contains_string("bundle.p12: Expected --password-file"))
    assert_that(captured.err, is_not(contains_string("README.txt")))


def test_ca_flag_flags_foreign_certificates_and_crls(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_bytes(_CA_CERT)
    foreign = tmp_path / "foreign.pem"
    foreign.write_bytes(_FOREIGN_CERT)
    foreign_crl = tmp_path / "foreign-crl.pem"
    foreign_crl.write_bytes(_FOREIGN_CRL)
    assert_that(_check(foreign, foreign_crl), equal_to(0))
    capsys.readouterr()
    assert_that(_check(foreign, foreign_crl, "--ca", str(ca)), equal_to(2))
    out = capsys.readouterr().out
    assert_that(out, contains_string("check: 2 untrusted"))


def test_pkcs12_with_password_file(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    bundle = tmp_path / "alice.p12"
    bundle.write_bytes(_P12)
    password_file = tmp_path / "password"
    password_file.write_text(_BUNDLE_PASSWORD + "\n")
    assert_that(_check(bundle, "--password-file", str(password_file), "--json"), equal_to(0))
    results = json.loads(capsys.readouterr().out)["results"]
    assert_that(sorted(r["kind"] for r in results), equal_to(["ca", "client"]))
    assert_that(_check(bundle, "--password-file", str(password_file), "--kind", "client"), equal_to(0))
    out = capsys.readouterr().out
    assert_that(out, contains_string("check: 1 ok"))


def test_no_store_needed_for_file_targets(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TINY_PKI_STORE", raising=False)
    cert = tmp_path / "server.pem"
    cert.write_bytes(_SERVER_CERT)
    main(["--color", "never", "check", str(cert)])
    assert_that(capsys.readouterr().out, contains_string("check: 1 ok"))


@pytest.mark.parametrize(
    ("setup", "words", "message"),
    [
        ("none", ("missing.pem",), "Expected a file or directory to check"),
        ("cert", ("server.pem", "--include-revoked"), "--include-revoked applies to the store only"),
        ("cert", ("--ca", "server.pem"), "--ca / --password-file apply to file targets"),
        ("cert", ("server.pem", "--ca", "junk.cer"), "Expected a PEM CA certificate for --ca"),
        ("cert", ("junk.cer",), "Expected a PEM or DER certificate or CRL"),
        ("cert", ("server.pem", "--ca", "server.pem"), "Expected a CA certificate (BasicConstraints ca=True) for --ca"),
        ("cert", ("bundle.p12",), "Expected --password-file to open the PKCS#12 bundle"),
        ("wrong", ("bundle.p12", "--password-file", "password"), "that opens with --password-file"),
    ],
)
def test_file_target_errors_exit_unknown(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    setup: str,
    words: tuple[str, ...],
    message: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    if setup != "none":
        (tmp_path / "server.pem").write_bytes(_SERVER_CERT)
        (tmp_path / "junk.cer").write_bytes(b"\x00not a certificate")
        (tmp_path / "bundle.p12").write_bytes(_P12)
        (tmp_path / "password").write_text("wrong-password-123\n")
    assert_that(_check(*words), equal_to(3))
    assert_that(capsys.readouterr().err, contains_string(message))


_BUNDLE_PASSWORD = "check-files-secret"
_CA_CERT, _CA_KEY = generate_ca_certificate("Files CA", key_size=2048)
_CLIENT_CERT, _CLIENT_KEY = generate_client_certificate(_CA_CERT, _CA_KEY, "alice", key_size=2048)
_CRL = generate_crl(_CA_CERT, _CA_KEY, [])
_FOREIGN_CA_CERT, _FOREIGN_CA_KEY = generate_ca_certificate("Foreign CA", key_size=2048)
_FOREIGN_CERT, _ = generate_client_certificate(_FOREIGN_CA_CERT, _FOREIGN_CA_KEY, "mallory", key_size=2048)
_FOREIGN_CRL = generate_crl(_FOREIGN_CA_CERT, _FOREIGN_CA_KEY, [])
_P12 = generate_pkcs12(_CLIENT_CERT, _CLIENT_KEY, _CA_CERT, "alice", _BUNDLE_PASSWORD.encode())
_SERVER_CERT, _SERVER_KEY = generate_server_certificate(_CA_CERT, _CA_KEY, "api.home", ["api.home"], key_size=2048)


def _check(*words: str | Path) -> int:
    try:
        main(["--color", "never", "check", *(str(word) for word in words)])
    except SystemExit as exited:
        return int(exited.code or 0)
    return 0
