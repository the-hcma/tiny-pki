"""PKCS#12 encryption modes and password policy (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import builtins
import getpass
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12
from hamcrest import assert_that, calling, contains_string, equal_to, is_, is_not, not_none, raises
from hamcrest.core.base_matcher import BaseMatcher
from hamcrest.core.description import Description
from pytest import CaptureFixture, MonkeyPatch
from pytest import raises as pytest_raises

from tiny_pki import (
    MIN_PKCS12_PASSWORD_LENGTH,
    generate_ca_certificate,
    generate_client_certificate,
    generate_pkcs12,
)
from tiny_pki.cli.main import main

# DER-encoded OBJECT IDENTIFIERs (tag + length + value).
_OID_PBES2 = bytes.fromhex("06092a864886f70d01050d")
_OID_PBE_SHA1_3DES = bytes.fromhex("060a2a864886f70d010c0103")
_OID_SHA1 = bytes.fromhex("06052b0e03021a")

_CA = generate_ca_certificate("P12 CA", key_size=2048)
_LEAF = generate_client_certificate(_CA[0], _CA[1], "carol", key_size=2048)


def test_cli_password_file(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    store = _cli_store(tmp_path, capsys)

    def _no_prompt(_prompt: str = "") -> str:
        raise AssertionError("prompted despite --password-file")

    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["", "n"])

    def _answer(_prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr(builtins, "input", _answer)
    removed_file = tmp_path / "removed-pw"
    removed_file.write_text("file-password\n")
    legacy_out = tmp_path / "legacy.p12"
    _cli(store, "export", "p12", "--legacy", "alice", "--password-file", str(removed_file), "--out", str(legacy_out))
    captured = capsys.readouterr()
    assert_that(captured.err, contains_string("holds the bundle password in plaintext"))
    assert_that(captured.out, contains_string(f"removed {removed_file}"))
    assert_that(removed_file.exists(), is_(False))
    assert_that(legacy_out.read_bytes(), _contains_bytes(_OID_PBE_SHA1_3DES))
    key, _, _ = pkcs12.load_key_and_certificates(legacy_out.read_bytes(), b"file-password")
    assert_that(key, is_(not_none()))

    kept_file = tmp_path / "kept-pw"
    kept_file.write_text("file-password")
    modern_out = tmp_path / "modern.p12"
    _cli(store, "export", "p12", "alice", "--password-file", str(kept_file), "--out", str(modern_out))
    assert_that(capsys.readouterr().err, contains_string(f"left {kept_file} in place"))
    assert_that(kept_file.is_file(), is_(True))
    assert_that(modern_out.read_bytes(), is_not(_contains_bytes(_OID_PBE_SHA1_3DES)))


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (None, "Expected a readable --password-file"),
        ("pw-utf16".encode("utf-16"), "Expected a UTF-8 --password-file"),
        ("\nsecond-line", "Expected a password on the first line"),
        ("short\n", f"at least {MIN_PKCS12_PASSWORD_LENGTH} bytes"),
    ],
)
def test_cli_password_file_rejected(
    tmp_path: Path, capsys: CaptureFixture[str], contents: str | bytes | None, message: str
) -> None:
    store = _cli_store(tmp_path, capsys)
    password_file = tmp_path / "pw"
    if isinstance(contents, bytes):
        password_file.write_bytes(contents)
    elif contents is not None:
        password_file.write_text(contents)
    out = tmp_path / "bad.p12"
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", "--password-file", str(password_file), "--out", str(out))
    assert_that(capsys.readouterr().err, contains_string(message))
    assert_that(out.exists(), is_(False))


@pytest.mark.parametrize(
    "words",
    [
        ("--password-file",),
        ("--password-file", "", "--out", "x.p12"),
        ("--password-file", "--legacy"),
        ("--out",),
    ],
)
def test_cli_path_flags_require_a_value(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch, words: tuple[str, ...]
) -> None:
    store = _cli_store(tmp_path, capsys)

    def _no_prompt(_prompt: str = "") -> str:
        raise AssertionError("fell back to the prompt")

    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", *words)
    assert_that(capsys.readouterr().err, contains_string("Expected a non-empty value for --"))


def test_cli_password_flag_removed(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _cli_store(tmp_path, capsys)
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", "--password", "argv-password")
    assert_that(capsys.readouterr().err, contains_string("Unknown flag --password"))


@pytest.mark.parametrize("entry", ["", EOFError(), KeyboardInterrupt()])
def test_cli_prompt_rejects_empty_or_aborted_entry(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch, entry: str | BaseException
) -> None:
    store = _cli_store(tmp_path, capsys)
    calls: list[str] = []

    def _type(prompt: str = "") -> str:
        calls.append(prompt)
        if isinstance(entry, BaseException):
            raise entry
        return entry

    monkeypatch.setattr(getpass, "getpass", _type)
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", "--out", str(tmp_path / "empty.p12"))
    assert_that(capsys.readouterr().err, contains_string("Expected a non-empty password"))
    assert_that(calls, equal_to(["PKCS#12 password: "]))


def test_cli_prompt_requires_matching_repeat(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store = _cli_store(tmp_path, capsys)
    typed = iter(["prompt-password", "prompt-password", "prompt-password", "typo-password"])

    def _type(_prompt: str = "") -> str:
        return next(typed)

    monkeypatch.setattr(getpass, "getpass", _type)
    good_out = tmp_path / "good.p12"
    _cli(store, "export", "p12", "alice", "--out", str(good_out))
    key, _, _ = pkcs12.load_key_and_certificates(good_out.read_bytes(), b"prompt-password")
    assert_that(key, is_(not_none()))
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", "--out", str(tmp_path / "typo.p12"))
    assert_that(capsys.readouterr().err, contains_string("repeated password to match"))


def test_default_bundle_uses_pbes2() -> None:
    p12 = generate_pkcs12(_LEAF[0], _LEAF[1], _CA[0], "carol", b"modern-pw")
    assert_that(p12, _contains_bytes(_OID_PBES2))
    assert_that(p12, is_not(_contains_bytes(_OID_PBE_SHA1_3DES)))
    assert_that(p12, is_not(_contains_bytes(_OID_SHA1)))


def test_legacy_bundle_uses_3des_and_round_trips() -> None:
    p12 = generate_pkcs12(_LEAF[0], _LEAF[1], _CA[0], "carol", b"legacy-pw", legacy=True)
    assert_that(p12, _contains_bytes(_OID_PBE_SHA1_3DES))
    assert_that(p12, _contains_bytes(_OID_SHA1))
    assert_that(p12, is_not(_contains_bytes(_OID_PBES2)))
    key, cert, extra = pkcs12.load_key_and_certificates(p12, b"legacy-pw")
    assert_that(key, is_(not_none()))
    assert_that(cert, is_(not_none()))
    assert_that(len(extra), equal_to(1))


def test_password_minimum_length() -> None:
    too_short = b"x" * (MIN_PKCS12_PASSWORD_LENGTH - 1)
    assert_that(
        calling(generate_pkcs12).with_args(_LEAF[0], _LEAF[1], _CA[0], "carol", too_short),
        raises(ValueError, f"at least {MIN_PKCS12_PASSWORD_LENGTH} bytes, got {len(too_short)}"),
    )
    generate_pkcs12(_LEAF[0], _LEAF[1], _CA[0], "carol", b"x" * MIN_PKCS12_PASSWORD_LENGTH)


class _ContainsBytes(BaseMatcher[bytes]):
    def __init__(self, needle: bytes) -> None:
        self._needle = needle

    def _matches(self, item: bytes) -> bool:
        return self._needle in item

    def describe_to(self, description: Description) -> None:
        description.append_text(f"bytes containing {self._needle.hex()}")


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _cli_store(tmp_path: Path, capsys: CaptureFixture[str]) -> Path:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    _cli(store, "create", "client", "alice", "--key-size", "2048")
    capsys.readouterr()
    return store


def _contains_bytes(needle: bytes) -> _ContainsBytes:
    return _ContainsBytes(needle)
