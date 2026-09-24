"""PKCS#12 encryption modes and password policy (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import getpass
from pathlib import Path

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


def test_cli_password_sources(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    _cli(store, "create", "client", "alice", "--key-size", "2048")
    capsys.readouterr()

    def _no_prompt(_prompt: str = "") -> str:
        raise AssertionError("prompted despite a supplied password")

    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    monkeypatch.setenv("TINY_PKI_P12_PASSWORD", "env-password")
    env_out = tmp_path / "env.p12"
    _cli(store, "export", "p12", "--legacy", "alice", "--out", str(env_out))
    captured = capsys.readouterr()
    assert_that(captured.err, equal_to(""))
    assert_that(env_out.read_bytes(), _contains_bytes(_OID_PBE_SHA1_3DES))
    key, _, _ = pkcs12.load_key_and_certificates(env_out.read_bytes(), b"env-password")
    assert_that(key, is_(not_none()))

    argv_out = tmp_path / "argv.p12"
    _cli(store, "export", "p12", "alice", "--password", "argv-password", "--out", str(argv_out))
    assert_that(capsys.readouterr().err, contains_string("--password is visible in shell/REPL history"))
    key, _, _ = pkcs12.load_key_and_certificates(argv_out.read_bytes(), b"argv-password")
    assert_that(key, is_(not_none()))
    assert_that(argv_out.read_bytes(), is_not(_contains_bytes(_OID_PBE_SHA1_3DES)))

    monkeypatch.setenv("TINY_PKI_P12_PASSWORD", "short")
    with pytest_raises(SystemExit):
        _cli(store, "export", "p12", "alice", "--out", str(tmp_path / "short.p12"))
    assert_that(capsys.readouterr().err, contains_string(f"at least {MIN_PKCS12_PASSWORD_LENGTH} bytes"))


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


def _contains_bytes(needle: bytes) -> _ContainsBytes:
    return _ContainsBytes(needle)
