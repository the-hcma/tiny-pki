"""Encrypted CA keys in the filesystem store and CLI."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import sys
from pathlib import Path

from hamcrest import assert_that, contains_string, equal_to, is_, is_not
from pytest import CaptureFixture, MonkeyPatch, raises

from tiny_pki import TinyPkiError, generate_ca_certificate
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, check_store

_SECRET = "s" * 32
_OTHER_SECRET = "x" * 32


def _run(
    store: Path,
    *words: str,
    capsys: CaptureFixture[str],
    expect_ok: bool = True,
) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with raises(SystemExit) as exited:
            main(argv)
        assert_that(exited.value.code, equal_to(1))
    captured = capsys.readouterr()
    return captured.out, captured.err


def test_encrypted_ca_key_requires_secret_only_for_signing(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_pair = generate_ca_certificate("Encrypted CA", key_size=2048)
    store.write_ca(*ca_pair, key_secret=_SECRET)
    store.publish_crl(key_secret=_SECRET)

    assert_that(store.ca_key_encrypted, is_(True))
    assert_that(ca_pair[1] not in store.ca_key_path.read_bytes(), is_(True))
    assert_that(store.read_ca_certificate(), equal_to(ca_pair[0]))
    assert_that(len(check_store(store)), equal_to(2))
    with raises(TinyPkiError, match="encrypted"):
        store.read_ca()
    with raises(TinyPkiError, match="incorrect"):
        store.read_ca(key_secret=_OTHER_SECRET)
    assert_that(store.read_ca(key_secret=_SECRET), equal_to(ca_pair))


def test_ca_key_migration_is_atomic_and_sets_secure_file_mode(tmp_path: Path) -> None:
    store = CertificateStore(tmp_path / "store")
    ca_pair = generate_ca_certificate("Migration CA", key_size=2048)
    store.write_ca(*ca_pair)
    store.ca_key_path.chmod(0o640)
    original_mode = store.ca_key_path.stat().st_mode & 0o777
    assert_that(original_mode, equal_to(0o640))

    store.encrypt_ca_key(_SECRET)
    encrypted_bytes = store.ca_key_path.read_bytes()
    assert_that(store.ca_key_encrypted, is_(True))
    assert_that(store.ca_key_path.stat().st_mode & 0o777, equal_to(0o600))
    with raises(TinyPkiError, match="incorrect"):
        store.decrypt_ca_key(_OTHER_SECRET)
    assert_that(store.ca_key_path.read_bytes(), equal_to(encrypted_bytes))

    store.decrypt_ca_key(_SECRET)
    assert_that(store.ca_key_encrypted, is_(False))
    assert_that(store.read_ca(), equal_to(ca_pair))
    assert_that(store.ca_key_path.stat().st_mode & 0o777, equal_to(0o600))


def test_store_encryption_uses_a_unique_salt(tmp_path: Path) -> None:
    ca_pair = generate_ca_certificate("Salted CA", key_size=2048)
    first = CertificateStore(tmp_path / "first")
    second = CertificateStore(tmp_path / "second")
    first.write_ca(*ca_pair, key_secret=_SECRET)
    second.write_ca(*ca_pair, key_secret=_SECRET)
    assert_that(first.ca_key_path.read_bytes(), is_not(equal_to(second.ca_key_path.read_bytes())))


def test_cli_encrypted_store_operations(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "key-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    _, error = _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )
    assert_that(error, is_not(contains_string("stored unencrypted")))
    store = CertificateStore(store_path)
    assert_that(store.ca_key_encrypted, is_(True))
    assert_that(store.ca_key_path.stat().st_mode & 0o777, equal_to(0o600))

    _run(store_path, "list", "ca", capsys=capsys)
    _run(store_path, "show", "ca", capsys=capsys)
    _run(store_path, "check", capsys=capsys)
    _, error = _run(store_path, "create", "client", "alice", capsys=capsys, expect_ok=False)
    assert_that(error, contains_string("key-secret-file"))
    _run(
        store_path,
        "create",
        "client",
        "alice",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )
    monkeypatch.setenv("TINY_PKI_KEY_SECRET_FILE", str(secret_file))
    _run(store_path, "create", "client", "bob", "--key-size", "2048", capsys=capsys)
    monkeypatch.delenv("TINY_PKI_KEY_SECRET_FILE")
    credentials_dir = tmp_path / "systemd-credentials"
    credentials_dir.mkdir()
    (credentials_dir / "tiny-pki-key").write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_dir))
    _run(store_path, "crl", capsys=capsys)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    pem_out = tmp_path / "alice.pem"
    _run(store_path, "export", "pem", "alice", "--out", str(pem_out), capsys=capsys)
    assert_that(pem_out.is_file(), is_(True))
    _run(store_path, "revoke", "alice", "--key-secret-file", str(secret_file), capsys=capsys)


def test_init_keeps_plaintext_default_even_with_secret_file_environment(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    monkeypatch.setenv("TINY_PKI_KEY_SECRET_FILE", str(tmp_path / "missing-secret"))

    _run(store_path, "init", "--key-size", "2048", capsys=capsys)
    store = CertificateStore(store_path)
    assert_that(store.ca_key_encrypted, is_(False))
    _, error = _run(
        store_path,
        "crl",
        "--key-secret-file",
        str(tmp_path / "missing-explicit-secret"),
        capsys=capsys,
        expect_ok=False,
    )
    assert_that(error, contains_string("--key-secret-file was given but the CA private key is not encrypted"))
    _run(store_path, "crl", capsys=capsys)


def test_encrypted_init_offers_to_remove_staging_secret_file(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "staging-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def confirm_removal(prompt: str) -> str:
        return "y"

    monkeypatch.setattr("builtins.input", confirm_removal)

    _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )

    assert_that(secret_file.exists(), is_(False))
    assert_that(CertificateStore(store_path).ca_key_encrypted, is_(True))


def test_encrypted_init_keeps_staging_secret_when_removal_is_not_confirmed(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "staging-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def decline_removal(prompt: str) -> str:
        return ""

    monkeypatch.setattr("builtins.input", decline_removal)

    _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )

    assert_that(secret_file.exists(), is_(True))


def test_encrypted_init_treats_eof_and_interrupt_as_no_removal(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    for name, failure in (("eof", EOFError), ("interrupt", KeyboardInterrupt)):
        store_path = tmp_path / name / "store"
        secret_file = tmp_path / name / "staging-secret"
        secret_file.parent.mkdir()
        secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")

        def decline_removal(prompt: str, *, error: type[BaseException] = failure) -> str:
            raise error

        monkeypatch.setattr("builtins.input", decline_removal)
        out, error_output = _run(
            store_path,
            "init",
            "--encrypt-key",
            "--key-secret-file",
            str(secret_file),
            "--key-size",
            "2048",
            capsys=capsys,
        )

        assert_that(out, contains_string("CA created"))
        assert_that(error_output, contains_string("left"))
        assert_that(secret_file.exists(), is_(True))
        assert_that(CertificateStore(store_path).ca_key_encrypted, is_(True))


def test_encrypted_init_keeps_configured_secret_file(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "staging-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setenv("TINY_PKI_KEY_SECRET_FILE", str(secret_file))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    _, error = _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )

    assert_that(secret_file.exists(), is_(True))
    assert_that(error, contains_string("TINY_PKI_KEY_SECRET_FILE points to this file"))


def test_encrypted_init_keeps_secret_file_under_credentials_directory(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    secret_file = credentials_dir / "staging-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_dir))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    _, error = _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )

    assert_that(secret_file.exists(), is_(True))
    assert_that(error, contains_string("under CREDENTIALS_DIRECTORY"))


def test_encrypted_init_warns_when_staging_secret_cannot_be_removed(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "staging-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def confirm_removal(prompt: str) -> str:
        return "y"

    monkeypatch.setattr("builtins.input", confirm_removal)
    original_unlink = Path.unlink

    def fail_secret_unlink(path: Path, *, missing_ok: bool = False) -> None:
        if path == secret_file:
            raise PermissionError("read-only")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_secret_unlink)

    _, error = _run(
        store_path,
        "init",
        "--encrypt-key",
        "--key-secret-file",
        str(secret_file),
        "--key-size",
        "2048",
        capsys=capsys,
    )

    assert_that(secret_file.exists(), is_(True))
    assert_that(CertificateStore(store_path).ca_key_encrypted, is_(True))
    assert_that(error, contains_string("could not remove"))


def test_cli_migrates_plaintext_ca_key_both_directions(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "key-secret"
    wrong_secret_file = tmp_path / "wrong-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    wrong_secret_file.write_text(f"{_OTHER_SECRET}\n", encoding="utf-8")
    store = CertificateStore(store_path)
    ca_pair = generate_ca_certificate("Migration CA", key_size=2048)
    store.write_ca(*ca_pair)
    store.publish_crl()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    _run(store_path, "encrypt-key", "--key-secret-file", str(secret_file), capsys=capsys)
    encrypted_bytes = store.ca_key_path.read_bytes()
    _, error = _run(
        store_path,
        "decrypt-key",
        "--key-secret-file",
        str(wrong_secret_file),
        capsys=capsys,
        expect_ok=False,
    )
    assert_that(error, contains_string("incorrect"))
    assert_that(store.ca_key_path.read_bytes(), equal_to(encrypted_bytes))
    _run(store_path, "decrypt-key", "--key-secret-file", str(secret_file), capsys=capsys)
    assert_that(store.read_ca(), equal_to(ca_pair))


def test_cli_warns_when_secret_file_is_group_or_world_accessible(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store_path = tmp_path / "store"
    secret_file = tmp_path / "key-secret"
    secret_file.write_text(f"{_SECRET}\n", encoding="utf-8")
    secret_file.chmod(0o640)
    store = CertificateStore(store_path)
    ca_pair = generate_ca_certificate("Protected CA", key_size=2048)
    store.write_ca(*ca_pair, key_secret=_SECRET)
    store.publish_crl(key_secret=_SECRET)

    _, error = _run(store_path, "crl", "--key-secret-file", str(secret_file), capsys=capsys)

    assert_that(error, contains_string("accessible to group or other users"))
