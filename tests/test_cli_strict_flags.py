"""Every CLI verb refuses unknown flags and extra positionals before writing (issue #121)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path

import pytest
from hamcrest import assert_that, contains_string, equal_to, is_, is_not, none, not_none
from pytest import CaptureFixture

from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore


def _run(store: Path, *words: str, capsys: CaptureFixture[str], expect_ok: bool = True) -> tuple[str, str]:
    argv = ["--store", str(store), "--color", "never", *words]
    if expect_ok:
        main(argv)
    else:
        with pytest.raises(SystemExit) as exited:
            main(argv)
        assert_that(exited.value.code, is_not(equal_to(0)))
    captured = capsys.readouterr()
    return captured.out, captured.err


def _snapshot(store: Path) -> dict[str, bytes]:
    return {str(p.relative_to(store)): p.read_bytes() for p in sorted(store.rglob("*")) if p.is_file()}


@pytest.fixture
def store(tmp_path: Path, capsys: CaptureFixture[str]) -> Path:
    root = tmp_path / "ca"
    _run(root, "init", "--key-size", "2048", capsys=capsys)
    _run(root, "create", "client", "alice", "--key-size", "2048", capsys=capsys)
    _run(root, "create", "client", "bob", "--key-size", "2048", capsys=capsys)
    _run(root, "revoke", "bob", capsys=capsys)
    return root


@pytest.mark.parametrize(
    ("words", "message"),
    [
        (("revoke", "alice", "--bogus"), "Unknown flag --bogus"),
        (("revoke", "alice", "carol"), "Unexpected extra arguments: carol"),
        (("revoke",), "Expected revoke"),
        (("delete", "bob", "--bogus"), "Unknown flag --bogus"),
        (("delete", "bob", "alice", "--force"), "Unexpected extra arguments: alice"),
        (("crl", "--bogus"), "Unknown flag --bogus"),
        (("crl", "extra"), "crl takes no positional arguments"),
        (("list", "clients", "--bogus"), "Unknown flag --bogus"),
        (("list", "clients", "servers"), "Unexpected extra arguments: servers"),
        (("show", "crl", "--json"), "Unknown flag --json"),
        (("show", "alice", "bob"), "Unexpected extra arguments: bob"),
        (("show", "clients", "--bogus"), "Unknown flag --bogus"),
        (("inspect", "alice", "--bogus"), "Unknown flag --bogus"),
        (("inspect", "alice", "bob"), "Unexpected extra arguments: bob"),
        (("export", "pem", "alice", "bob"), "Unexpected extra arguments: bob"),
        (("export", "pem", "alice", "--bogus"), "Unknown flag --bogus"),
        (("check", "--bogus"), "Unknown flag --bogus"),
    ],
)
def test_bad_arguments_exit_nonzero_and_leave_the_store_unchanged(
    store: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, words: tuple[str, ...], message: str
) -> None:
    monkeypatch.chdir(store.parent)
    before = _snapshot(store)
    _, err = _run(store, *words, capsys=capsys, expect_ok=False)
    assert_that(err, contains_string(message))
    assert_that(_snapshot(store), equal_to(before))
    assert_that(list(store.parent.glob("*.pem")), equal_to([]))


def test_revoke_dry_run_previews_without_revoking(store: Path, capsys: CaptureFixture[str]) -> None:
    before = _snapshot(store)
    out, _ = _run(store, "revoke", "alice", "--dry-run", capsys=capsys)
    assert_that(out, contains_string("would revoke client alice"))
    assert_that(out, contains_string("nothing written"))
    assert_that(_snapshot(store), equal_to(before))
    entry = CertificateStore(store).get_certificate("alice")
    assert entry is not None
    assert_that(entry.revoked_at, is_(none()))


def test_revoke_dry_run_on_revoked_entry_reports_nothing_to_do(store: Path, capsys: CaptureFixture[str]) -> None:
    out, _ = _run(store, "revoke", "bob", "--dry-run", capsys=capsys)
    assert_that(out, contains_string("already revoked"))


def test_revoke_dry_run_of_unknown_identity_fails(store: Path, capsys: CaptureFixture[str]) -> None:
    _, err = _run(store, "revoke", "carol", "--dry-run", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("carol"))


def test_delete_dry_run_previews_without_deleting(store: Path, capsys: CaptureFixture[str]) -> None:
    before = _snapshot(store)
    out, _ = _run(store, "delete", "bob", "--dry-run", capsys=capsys)
    assert_that(out, contains_string("would delete client bob"))
    out, _ = _run(store, "delete", "alice", "--force", "--dry-run", capsys=capsys)
    assert_that(out, contains_string("would revoke and delete client alice"))
    assert_that(_snapshot(store), equal_to(before))
    assert_that(CertificateStore(store).get_certificate("alice"), is_(not_none()))


def test_delete_dry_run_of_active_entry_without_force_fails(store: Path, capsys: CaptureFixture[str]) -> None:
    before = _snapshot(store)
    _, err = _run(store, "delete", "alice", "--dry-run", capsys=capsys, expect_ok=False)
    assert_that(err, contains_string("still active"))
    assert_that(_snapshot(store), equal_to(before))


def test_list_json_still_works_in_any_position(store: Path, capsys: CaptureFixture[str]) -> None:
    out, _ = _run(store, "list", "--json", "clients", capsys=capsys)
    assert_that(out, contains_string('"cn": "alice"'))
    out, _ = _run(store, "show", "clients", "--json", capsys=capsys)
    assert_that(out, contains_string('"cn": "alice"'))
