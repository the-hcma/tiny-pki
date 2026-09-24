"""CN / organization / SAN validation and normalization (issue #32)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import builtins
import random
import string
import sys
import warnings
from pathlib import Path
from typing import cast

import pytest
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    equal_to,
    has_item,
    has_length,
    is_not,
    none,
    not_none,
    raises,
)
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki import (
    TinyPkiWarning,
    generate_ca_certificate,
    generate_client_certificate,
    generate_server_certificate,
    get_certificate_sans,
    get_certificate_subject,
)
from tiny_pki.cli.main import main
from tiny_pki.names import (
    MAX_COMMON_NAME_LENGTH,
    common_name_as_san,
    normalize_dns_name,
    normalize_san_entries,
    normalize_san_entry,
    normalize_subject_attribute,
)
from tiny_pki.store import CertificateStore, IssuedCertificate

_CA = generate_ca_certificate("Names CA", key_size=2048)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("API.Home.", "api.home"),
        ("  api.home  ", "api.home"),
        ("bücher.home", "xn--bcher-kva.home"),
        ("*.lan.home", "*.lan.home"),
        ("2001:DB8::1", "2001:db8::1"),
        ("192.168.1.10", "192.168.1.10"),
        ("::1", "::1"),
    ],
)
def test_normalize_san_entry_accepts(raw: str, expected: str) -> None:
    assert_that(normalize_san_entry(raw), equal_to(expected))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "non-empty SAN"),
        ("https://api.home", "not a URL"),
        ("api.home:443", "without a port"),
        ("10.0.0.0/24", "not a CIDR range"),
        ("fe80::1%eth0", "without a zone ID"),
        ("api home.lan", "without whitespace"),
        ("api..home", "without empty labels"),
        ("*.home", "at least two labels"),
        ("x.*.home", "entire leftmost label"),
        ("a*.lan.home", "letters, digits, and inner hyphens"),
        ("faß.de", "encodes unambiguously"),
        ("ſ.home", "encodes unambiguously"),
        ("under_score.home", "letters, digits, and inner hyphens"),
        ("-bad.home", "letters, digits, and inner hyphens"),
        ("a" * 64 + ".home", "letters, digits, and inner hyphens"),
        (".".join(["a" * 60] * 5), "at most 253 characters"),
        ("192.168.1", "last label is not numeric"),
        ("192.168.001.010", "last label is not numeric"),
    ],
)
def test_normalize_san_entry_rejects(raw: str, message: str) -> None:
    assert_that(calling(normalize_san_entry).with_args(raw), raises(ValueError, message))


def test_normalize_san_entries_dedupes_in_order() -> None:
    assert_that(
        normalize_san_entries(["a.home", "A.HOME.", "10.0.0.1", "a.home"]),
        equal_to(["a.home", "10.0.0.1"]),
    )
    assert_that(calling(normalize_san_entries).with_args([]), raises(ValueError, "at least one SAN"))


def test_normalize_dns_name_randomized_idempotent_and_case_insensitive() -> None:
    rng = random.Random(32)
    alphabet = string.ascii_letters + string.digits
    for _ in range(500):
        labels = [_random_label(rng, alphabet) for _ in range(rng.randint(1, 4))]
        tld = rng.choice(string.ascii_letters) + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 5)))
        name = ".".join([*labels, tld]) + rng.choice(["", "."])
        once = normalize_dns_name(name)
        assert_that(normalize_dns_name(once), equal_to(once))
        assert_that(normalize_dns_name(name.swapcase()), equal_to(once))
        assert_that(once, equal_to(once.lower()))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("   ", "non-empty common_name"),
        ("a" * (MAX_COMMON_NAME_LENGTH + 1), f"at most {MAX_COMMON_NAME_LENGTH} characters"),
        ("ali\x00ce", "control or format characters"),
        ("ali\nce", "control or format characters"),
        ("ali\u200bce", "control or format characters"),
    ],
)
def test_normalize_subject_attribute_rejects(raw: str, message: str) -> None:
    assert_that(
        calling(normalize_subject_attribute).with_args(raw, "common_name", max_length=MAX_COMMON_NAME_LENGTH),
        raises(ValueError, message),
    )


def test_normalize_subject_attribute_strips_and_keeps_unicode() -> None:
    value = normalize_subject_attribute("  José's phone ", "common_name", max_length=MAX_COMMON_NAME_LENGTH)
    assert_that(value, equal_to("José's phone"))


def test_common_name_as_san() -> None:
    assert_that(common_name_as_san("API.home"), equal_to("api.home"))
    assert_that(common_name_as_san("Alice Phone"), none())


def test_issuance_strips_cn_and_rejects_bad_org() -> None:
    ca_cert, ca_key = _CA
    cert_pem, _ = generate_client_certificate(ca_cert, ca_key, "  alice  ", key_size=2048)
    assert_that(get_certificate_subject(cert_pem), equal_to("alice"))
    assert_that(
        calling(generate_client_certificate).with_args(
            ca_cert, ca_key, "alice", organization_name="Ac\tme", key_size=2048
        ),
        raises(ValueError, "organization_name without control"),
    )
    assert_that(
        calling(generate_ca_certificate).with_args("x" * 65, key_size=2048),
        raises(ValueError, "common_name of at most 64"),
    )


def test_server_normalizes_sans_and_auto_adds_cn_with_warning() -> None:
    ca_cert, ca_key = _CA
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cert_pem, _ = generate_server_certificate(
            ca_cert, ca_key, "API.home", ["Alias.Home.", "alias.home", "192.168.1.10"], key_size=2048
        )
    assert_that(get_certificate_sans(cert_pem), equal_to(["alias.home", "api.home", "192.168.1.10"]))
    assert_that(caught, has_length(1))
    assert_that(caught[0].category, equal_to(TinyPkiWarning))
    assert_that(caught[0].filename, contains_string("test_names"))

    cert_pem, _ = generate_server_certificate(
        ca_cert, ca_key, "api.home", ["alias.home"], key_size=2048, include_common_name_in_sans=False
    )
    assert_that(get_certificate_sans(cert_pem), is_not(has_item("api.home")))


def test_server_rejects_invalid_san() -> None:
    ca_cert, ca_key = _CA
    assert_that(
        calling(generate_server_certificate).with_args(
            ca_cert, ca_key, "api.home", ["https://api.home"], key_size=2048
        ),
        raises(ValueError, "not a URL"),
    )


def test_cli_cn_in_san_prompt(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["n", ""])

    def _answer(_prompt: str) -> str:
        return next(answers)

    monkeypatch.setattr(builtins, "input", _answer)
    _cli(store, "create", "server", "one.home", "--san", "alias1.home", "--key-size", "2048")
    _cli(store, "create", "server", "two.home", "--san", "alias2.home", "--key-size", "2048")
    assert_that(_sans(store, "one.home"), equal_to(["alias1.home"]))
    assert_that(_sans(store, "two.home"), equal_to(["alias2.home", "two.home"]))
    assert_that(capsys.readouterr().err, contains_string("Added common_name 'two.home'"))

    def _no_prompt(_prompt: str) -> str:
        raise AssertionError("prompted despite --yes / --no-cn-san")

    monkeypatch.setattr(builtins, "input", _no_prompt)
    _cli(store, "create", "server", "three.home", "--san", "alias3.home", "--yes", "--key-size", "2048")
    _cli(store, "create", "server", "four.home", "--san", "alias4.home", "--no-cn-san", "--key-size", "2048")
    assert_that(_sans(store, "three.home"), has_item("three.home"))
    assert_that(_sans(store, "four.home"), equal_to(["alias4.home"]))


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("client", "alice", "--no-cn-san"), "only supported for server certificates"),
        (("client", "alice", "--yes"), "only supported for server certificates"),
        (("server", "api.home", "--no-cn-san"), "Expected --san with --no-cn-san"),
    ],
)
def test_cli_cn_san_flag_misuse(
    tmp_path: Path, capsys: CaptureFixture[str], words: tuple[str, ...], message: str
) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _cli(store, "create", *words, "--key-size", "2048")
    assert_that(capsys.readouterr().err, contains_string(message))


def test_cli_non_interactive_adds_cn(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch) -> None:
    store = tmp_path / "ca"
    _cli(store, "init", "--key-size", "2048")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    _cli(store, "create", "server", "api.home", "--san", "alias.home", "--key-size", "2048")
    assert_that(_sans(store, "api.home"), equal_to(["alias.home", "api.home"]))
    assert_that(capsys.readouterr().err, contains_string("warning: Added common_name"))


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _random_label(rng: random.Random, alphabet: str) -> str:
    middle = "".join(rng.choice(alphabet + "-") for _ in range(rng.randint(0, 18)))
    return rng.choice(alphabet) + middle + rng.choice(alphabet)


def _sans(store: Path, identity: str) -> list[str]:
    cs = CertificateStore(store)
    entry = cs.get_certificate(identity)
    assert_that(entry, not_none())
    return get_certificate_sans(cs.read_certificate_pem(cast(IssuedCertificate, entry)))
