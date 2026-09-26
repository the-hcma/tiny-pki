"""Exports must never write the leaf key through a symlink at the destination (issue #96)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from hamcrest import assert_that, contains_string, equal_to
from pytest import CaptureFixture, MonkeyPatch

from tiny_pki._fsutil import write_file_atomic
from tiny_pki.cli.main import main

_PASSWORD = "export-symlink-password"


def _cli(store: Path, *words: str) -> None:
    main(["--store", str(store), "--color", "never", *words])


def _store_with_alice(tmp_path: Path) -> Path:
    store = tmp_path / "store"
    _cli(store, "init", "--cn", "Symlink CA", "--key-size", "2048")
    _cli(store, "create", "client", "alice", "--key-size", "2048")
    return store


def _planted_link(link: Path, tmp_path: Path) -> Path:
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    link.symlink_to(victim)
    return victim


def _export_refused(store: Path, capsys: CaptureFixture[str], *words: str) -> None:
    with pytest.raises(SystemExit) as exited:
        _cli(store, "export", *words)
    assert_that(exited.value.code, equal_to(1))
    assert_that(capsys.readouterr().err, contains_string("to not already exist as a symlink"))


def test_export_pem_default_path_refuses_symlink(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: MonkeyPatch
) -> None:
    store = _store_with_alice(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    victim = _planted_link(out_dir / "alice.pem", tmp_path)
    monkeypatch.chdir(out_dir)
    capsys.readouterr()
    _export_refused(store, capsys, "pem", "alice")
    assert_that(victim.read_text(), equal_to("untouched"))


def test_export_pem_out_refuses_symlink(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store_with_alice(tmp_path)
    link = tmp_path / "alice-out.pem"
    victim = _planted_link(link, tmp_path)
    capsys.readouterr()
    _export_refused(store, capsys, "pem", "alice", "--out", str(link))
    assert_that(victim.read_text(), equal_to("untouched"))


def test_export_p12_out_refuses_symlink(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store_with_alice(tmp_path)
    password_file = tmp_path / "pw"
    password_file.write_text(_PASSWORD)
    link = tmp_path / "alice.p12"
    victim = _planted_link(link, tmp_path)
    capsys.readouterr()
    _export_refused(store, capsys, "p12", "alice", "--password-file", str(password_file), "--out", str(link))
    assert_that(victim.read_text(), equal_to("untouched"))


def test_export_pem_replaces_existing_file_with_mode_0600(tmp_path: Path) -> None:
    store = _store_with_alice(tmp_path)
    out = tmp_path / "alice.pem"
    out.write_text("stale")
    out.chmod(0o644)
    _cli(store, "export", "pem", "alice", "--out", str(out))
    assert_that(out.read_text(), contains_string("PRIVATE KEY"))
    assert_that(stat.S_IMODE(out.stat().st_mode), equal_to(0o600))


def test_write_file_atomic_leaves_no_temp_file_on_failure(tmp_path: Path) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(IsADirectoryError):
        write_file_atomic(occupied, b"secret key bytes", mode=0o600)
    assert_that([p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")], equal_to([]))
    target = tmp_path / "ok"
    write_file_atomic(target, b"data", mode=0o640)
    assert_that(target.read_bytes(), equal_to(b"data"))
    assert_that(stat.S_IMODE(target.stat().st_mode), equal_to(0o640))
    assert_that([p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")], equal_to([]))


def test_write_file_atomic_replaces_link_planted_after_the_check(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    link = tmp_path / "alice.pem"
    link.symlink_to(victim)

    def never_a_symlink(self: Path) -> bool:
        return False

    monkeypatch.setattr(Path, "is_symlink", never_a_symlink)
    write_file_atomic(link, b"key material", mode=0o600)
    monkeypatch.undo()
    assert_that(victim.read_text(), equal_to("untouched"))
    assert_that(link.is_symlink(), equal_to(False))
    assert_that(link.read_bytes(), equal_to(b"key material"))
    assert_that(stat.S_IMODE(link.stat().st_mode), equal_to(0o600))


def test_write_file_atomic_sets_mode_without_fchmod(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delattr("tiny_pki._fsutil.os.fchmod")
    target = tmp_path / "secret.pem"
    write_file_atomic(target, b"data", mode=0o640)
    assert_that(stat.S_IMODE(target.stat().st_mode), equal_to(0o640))
    assert_that(target.read_bytes(), equal_to(b"data"))
