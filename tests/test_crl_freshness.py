"""Short CRL lifetimes, the renewal check, the publish hook and CRL Distribution Points (issue #159)."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from hamcrest import (
    assert_that,
    calling,
    contains_string,
    equal_to,
    has_entries,
    has_item,
    is_,
    none,
    not_,
    raises,
)
from pytest import CaptureFixture

from tiny_pki import (
    DEFAULT_CRL_VALIDITY_DAYS,
    Status,
    TinyPkiError,
    check_crl,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_server_certificate,
)
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore, check_store

_CA = generate_ca_certificate("Freshness CA", key_type="ec-p256")
_CRL_URL = "http://pki.home/crl.pem"


def _run(store: Path, *words: str, capsys: CaptureFixture[str]) -> tuple[int, str, str]:
    try:
        main(["--store", str(store), "--color", "never", *words])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _store(tmp_path: Path) -> CertificateStore:
    store = CertificateStore(tmp_path / "store")
    store.write_ca(*_CA)
    store.publish_crl()
    return store


def test_the_default_crl_lifetime_is_a_week() -> None:
    crl = x509.load_pem_x509_crl(generate_crl(*_CA, []))
    assert crl.next_update_utc is not None
    assert_that(DEFAULT_CRL_VALIDITY_DAYS, equal_to(7))
    assert_that((crl.next_update_utc - crl.last_update_utc).days, equal_to(7))


@pytest.mark.parametrize(("interval", "status"), [(timedelta(hours=12), Status.OK), (timedelta(days=3), Status.OK)])
def test_a_week_long_crl_suits_a_daily_or_three_day_renewal(interval: timedelta, status: Status) -> None:
    assert_that(check_crl(generate_crl(*_CA, []), renewal_interval=interval).status, equal_to(status))


def test_a_lifetime_under_twice_the_interval_is_expiring() -> None:
    result = check_crl(generate_crl(*_CA, [], validity_days=7), renewal_interval=timedelta(days=4))
    assert_that(result.status, equal_to(Status.EXPIRING))
    assert_that(result.reasons, has_item(contains_string("one missed renewal would let it lapse")))


def test_a_crl_expiring_before_the_next_renewal_is_expiring() -> None:
    crl_pem = generate_crl(*_CA, [], validity_days=7)
    crl = x509.load_pem_x509_crl(crl_pem)
    assert crl.next_update_utc is not None
    late = crl.next_update_utc - timedelta(hours=12)
    result = check_crl(crl_pem, now=late, within=timedelta(0), renewal_interval=timedelta(days=1))
    assert_that(result.status, equal_to(Status.EXPIRING))
    assert_that(result.reasons, has_item(contains_string("before the next renewal")))
    assert_that(check_crl(crl_pem, now=late, within=timedelta(0)).status, equal_to(Status.OK))


@pytest.mark.parametrize("interval", [timedelta(0), timedelta(hours=-1)])
def test_a_non_positive_interval_is_refused(interval: timedelta) -> None:
    assert_that(
        calling(check_crl).with_args(generate_crl(*_CA, []), renewal_interval=interval),
        raises(TinyPkiError, "positive renewal_interval"),
    )


def test_a_one_day_store_crl_renews_and_checks_against_its_timer(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_crl_validity_days(1)
    store.publish_crl()
    crl = x509.load_pem_x509_crl(store.read_crl() or b"")
    assert crl.next_update_utc is not None
    assert_that((crl.next_update_utc - crl.last_update_utc).days, equal_to(1))
    hourly = dict(check_store(store, crl_renewal_interval=timedelta(hours=1)))
    daily = dict(check_store(store, crl_renewal_interval=timedelta(days=1)))
    assert_that(hourly["crl"].status, equal_to(Status.OK))
    assert_that(daily["crl"].status, equal_to(Status.EXPIRING))


def test_cli_check_crl_renewal(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = _store(tmp_path).root
    assert_that(_run(root, "check", "--crl-renewal", "1d", capsys=capsys)[0], equal_to(0))
    code, out, _ = _run(root, "check", "--crl-renewal", "7d", "--kind", "crl", capsys=capsys)
    assert_that(code, equal_to(1))
    assert_that(out, contains_string("expiring"))
    code, _, err = _run(root, "check", "--crl-renewal", "1w", capsys=capsys)
    assert_that(code, not_(equal_to(0)))
    assert_that(err, contains_string("--crl-renewal"))


def test_cli_check_crl_renewal_on_a_crl_file(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    crl_path = tmp_path / "crl.pem"
    crl_path.write_bytes(generate_crl(*_CA, [], validity_days=1))
    code, _, _ = _main_without_store(["check", str(crl_path), "--crl-renewal", "18h"], capsys)
    assert_that(code, equal_to(1))
    assert_that(_main_without_store(["check", str(crl_path), "--crl-renewal", "6h"], capsys)[0], equal_to(0))


def _main_without_store(words: list[str], capsys: CaptureFixture[str]) -> tuple[int, str, str]:
    try:
        main(["--color", "never", *words])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _distribution_point(cert_pem: bytes) -> list[x509.DistributionPoint] | None:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return None
    assert_that(ext.critical, is_(False))
    return list(ext.value)


def test_leaves_carry_a_crl_distribution_point_only_when_asked() -> None:
    expected = [x509.DistributionPoint([x509.UniformResourceIdentifier(_CRL_URL)], None, None, None)]
    server, _ = generate_server_certificate(*_CA, "api.home", ["api.home"], key_type="ec-p256", crl_url=_CRL_URL)
    client, _ = generate_client_certificate(*_CA, "alice", key_type="ec-p256", crl_url=_CRL_URL)
    assert_that(_distribution_point(server), equal_to(expected))
    assert_that(_distribution_point(client), equal_to(expected))
    assert_that(_distribution_point(generate_client_certificate(*_CA, "bob", key_type="ec-p256")[0]), is_(none()))


@pytest.mark.parametrize("url", ["ftp://pki.home/crl.pem", "pki.home/crl.pem", "http://"])
def test_a_bad_crl_url_is_refused(url: str) -> None:
    assert_that(
        calling(generate_client_certificate).with_args(*_CA, "alice", key_type="ec-p256", crl_url=url),
        raises(TinyPkiError),
    )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_reads_the_crl_distribution_point(tmp_path: Path) -> None:
    cert, _ = generate_client_certificate(*_CA, "alice", key_type="ec-p256", crl_url=_CRL_URL)
    (tmp_path / "leaf.pem").write_bytes(cert)
    text = subprocess.run(
        ["openssl", "x509", "-in", "leaf.pem", "-noout", "-text"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert_that(text, contains_string("X509v3 CRL Distribution Points"))
    assert_that(text, contains_string(f"URI:{_CRL_URL}"))


def test_store_crl_url_applies_to_new_leaves_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = store.issue_client("before", key_type="ec-p256")
    store.set_crl_url(_CRL_URL)
    assert_that(CertificateStore(store.root).crl_url, equal_to(_CRL_URL))
    after = store.issue_client("after", key_type="ec-p256")
    assert_that(_distribution_point(store.read_certificate_pem(before)), is_(none()))
    assert_that(_distribution_point(store.read_certificate_pem(after)), not_(none()))
    store.set_crl_url(None)
    assert_that(store.crl_url, is_(none()))
    assert_that(calling(store.set_crl_url).with_args("file:///etc/crl.pem"), raises(TinyPkiError))


def test_cli_crl_url(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = _store(tmp_path).root
    assert_that(_run(root, "crl", "url", capsys=capsys)[1], contains_string("no CRL URL"))
    assert_that(_run(root, "crl", "url", _CRL_URL, capsys=capsys)[1], contains_string("DER"))
    assert_that(_run(root, "crl", "url", capsys=capsys)[1].strip(), equal_to(_CRL_URL))
    assert_that(json.loads(_run(root, "list", "ca", "--json", capsys=capsys)[1]), has_entries(crl_url=_CRL_URL))
    _run(root, "create", "server", "api.home", "--key-type", "ec-p256", "--yes", capsys=capsys)
    entry = CertificateStore(root).get_certificate("api.home")
    assert entry is not None
    assert_that(_distribution_point(CertificateStore(root).read_certificate_pem(entry)), not_(none()))
    _run(root, "crl", "url", "--clear", capsys=capsys)
    assert_that(CertificateStore(root).crl_url, is_(none()))
    code, _, err = _run(root, "crl", "url", _CRL_URL, "--clear", capsys=capsys)
    assert_that(code, equal_to(1))
    assert_that(err, contains_string("not both"))


@pytest.fixture
def hook(tmp_path: Path) -> tuple[Path, str]:
    """A hook command that logs each run (cwd and the TINY_PKI_* variables) and exits with a code from a file."""
    script = tmp_path / "hook.py"
    log = tmp_path / "hook.log"
    script.write_text(
        "import json, os, pathlib, sys\n"
        "log = pathlib.Path(sys.argv[1])\n"
        "env = {k: v for k, v in os.environ.items() if k.startswith('TINY_PKI_')}\n"
        "with log.open('a') as handle:\n"
        "    handle.write(json.dumps({'cwd': os.getcwd(), 'env': env}) + '\\n')\n"
        "code = pathlib.Path(sys.argv[1] + '.code')\n"
        "sys.exit(int(code.read_text()) if code.exists() else 0)\n"
    )
    return log, f"{sys.executable} {script} {log}"


def _hook_runs(log: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_cli_runs_the_hook_after_every_publish(
    tmp_path: Path, hook: tuple[Path, str], capsys: CaptureFixture[str]
) -> None:
    log, command = hook
    store = _store(tmp_path)
    root = store.root
    assert_that(_run(root, "crl", "hook", command, capsys=capsys)[0], equal_to(0))
    assert_that(_hook_runs(log), equal_to([]))
    assert_that(_run(root, "crl", "hook", capsys=capsys)[1].strip(), equal_to(command))
    _run(root, "create", "client", "alice", "--key-type", "ec-p256", capsys=capsys)
    runs_after_create = len(_hook_runs(log))
    _run(root, "list", capsys=capsys)
    _run(root, "check", capsys=capsys)
    assert_that(len(_hook_runs(log)), equal_to(runs_after_create))
    _run(root, "revoke", "alice", capsys=capsys)
    _run(root, "crl", capsys=capsys)
    runs = _hook_runs(log)
    assert_that(len(runs), equal_to(runs_after_create + 2))
    assert_that(
        runs[-1],
        equal_to(
            {
                "cwd": str(root),
                "env": {
                    "TINY_PKI_CRL": str(root / "public" / "crl.pem"),
                    "TINY_PKI_OCSP_DIR": str(root / "public" / "ocsp"),
                    "TINY_PKI_STORE": str(root),
                },
            }
        ),
    )
    assert_that(json.loads(_run(root, "list", "ca", "--json", capsys=capsys)[1]), has_entries(publish_hook=command))
    assert_that(_run(root, "list", "ca", capsys=capsys)[1], not_(contains_string(command)))
    _run(root, "crl", "hook", "--clear", capsys=capsys)
    _run(root, "crl", capsys=capsys)
    assert_that(len(_hook_runs(log)), equal_to(len(runs)))


def test_ocsp_publishes_run_the_hook(tmp_path: Path, hook: tuple[Path, str], capsys: CaptureFixture[str]) -> None:
    log, command = hook
    store = _store(tmp_path)
    store.issue_server("api.home", ["api.home"], key_type="ec-p256")
    store.set_publish_hook(command)
    _run(store.root, "ocsp", capsys=capsys)
    assert_that(len(_hook_runs(log)), equal_to(1))


def test_a_failing_hook_fails_the_command_but_keeps_the_publish(
    tmp_path: Path, hook: tuple[Path, str], capsys: CaptureFixture[str]
) -> None:
    log, command = hook
    Path(f"{log}.code").write_text("3")
    store = _store(tmp_path)
    store.set_publish_hook(command)
    before = store.read_crl()
    code, _, err = _run(store.root, "crl", capsys=capsys)
    assert_that(code, equal_to(1))
    assert_that(err, contains_string("published, but the publish hook exited 3"))
    assert_that(err, not_(contains_string(command)))
    assert_that(store.read_crl(), not_(equal_to(before)))


def test_a_missing_hook_command_is_reported(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    store = _store(tmp_path)
    store.set_publish_hook(str(tmp_path / "no-such-command"))
    code, _, err = _run(store.root, "crl", capsys=capsys)
    assert_that(code, equal_to(1))
    assert_that(err, contains_string("publish hook failed"))


@pytest.mark.parametrize("command", ["", "   ", "reload\nnginx", "sh -c 'unbalanced"])
def test_bad_hook_commands_are_refused(tmp_path: Path, command: str) -> None:
    store = _store(tmp_path)
    assert_that(calling(store.set_publish_hook).with_args(command), raises(TinyPkiError))
    assert_that(store.publish_hook, is_(none()))


def test_library_calls_never_run_the_hook_on_their_own(tmp_path: Path, hook: tuple[Path, str]) -> None:
    log, command = hook
    store = _store(tmp_path)
    assert_that(store.run_publish_hook(), is_(none()))
    store.set_publish_hook(command)
    store.issue_client("alice", key_type="ec-p256")
    store.revoke("alice")
    assert_that(_hook_runs(log), equal_to([]))
    assert_that(store.run_publish_hook(), equal_to(0))
    assert_that(len(_hook_runs(log)), equal_to(1))


def test_the_hook_times_out(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_publish_hook(f"{sys.executable} -c 'import time; time.sleep(5)'")
    assert_that(calling(store.run_publish_hook).with_args(timeout=0.2), raises(TinyPkiError, "within 0.2 seconds"))


def test_cli_crl_rejects_misplaced_arguments(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = _store(tmp_path).root
    for words, message in (
        (("crl", "hook", "a", "b"), "quote it"),
        (("crl", "url", "--days", "3"), "only supported when publishing"),
        (("crl", "--clear"), "--clear is only supported"),
        (("crl", "now"), "Expected crl, crl hook or crl url"),
    ):
        code, _, err = _run(root, *words, capsys=capsys)
        assert_that(code, not_(equal_to(0)))
        assert_that(err, contains_string(message))
