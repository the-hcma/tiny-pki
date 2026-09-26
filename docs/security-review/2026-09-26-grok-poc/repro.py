"""Independent security-review reproductions. Writes only under /tmp."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tiny_pki import (
    check_certificate,
    generate_ca_certificate,
    generate_client_certificate,
    generate_crl,
    generate_pkcs12,
    generate_server_certificate,
    get_certificate_serial_number,
)
from tiny_pki.check import Status
from tiny_pki.cli.main import main
from tiny_pki.store import CertificateStore

REPO_ROOT = os.environ.get("TINY_PKI_REPO", str(Path(__file__).resolve().parents[3]))

def section(title: str) -> None:
    print(f"\n===== {title} =====")


def run_cli(store: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "run", "tiny-pki", "--store", str(store), "--color", "never", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def openssl_verify(ca_pem: Path, leaf_pem: Path, crl_pem: Path | None = None) -> str:
    cmd = ["openssl", "verify", "-CAfile", str(ca_pem)]
    if crl_pem is not None:
        cmd += ["-crl_check", "-CRLfile", str(crl_pem)]
    cmd.append(str(leaf_pem))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return f"rc={proc.returncode} stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}"


def main_repro() -> None:
    root = Path(tempfile.mkdtemp(prefix="tiny-pki-poc-"))
    print(f"workdir {root}")

    # --- extensions / AKI consistency ---
    section("leaf and CRL extensions")
    ca_cert, ca_key = generate_ca_certificate(
        "Home CA", organization_name="tiny-pki", key_size=2048, permitted_subtrees=["home", "192.168.0.0/16"]
    )
    client_cert, client_key = generate_client_certificate(ca_cert, ca_key, "alice", key_size=2048)
    server_cert, server_key = generate_server_certificate(
        ca_cert, ca_key, "api.home", ["api.home", "192.168.1.10"], key_size=2048
    )
    serial = get_certificate_serial_number(client_cert)
    crl_pem = generate_crl(ca_cert, ca_key, [(serial, datetime.now(UTC))])

    def dump(label: str, pem: bytes, kind: str) -> None:
        if kind == "cert":
            obj = x509.load_pem_x509_certificate(pem)
            bc = obj.extensions.get_extension_for_class(x509.BasicConstraints)
            ku = obj.extensions.get_extension_for_class(x509.KeyUsage)
            print(f"{label} BC critical={bc.critical} ca={bc.value.ca} pathlen={bc.value.path_length}")
            print(
                f"{label} KU critical={ku.critical} digsig={ku.value.digital_signature} "
                f"keyCertSign={ku.value.key_cert_sign} crlSign={ku.value.crl_sign} "
                f"keyEncipher={ku.value.key_encipherment}"
            )
            try:
                eku = obj.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
                print(f"{label} EKU critical={eku.critical} {list(eku.value)}")
            except x509.ExtensionNotFound:
                print(f"{label} EKU absent")
            try:
                san = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                print(f"{label} SAN critical={san.critical} {list(san.value)}")
            except x509.ExtensionNotFound:
                print(f"{label} SAN absent")
            ski = obj.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            print(f"{label} SKI {ski.hex()}")
            try:
                aki = obj.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
                print(f"{label} AKI {aki.key_identifier.hex() if aki.key_identifier else None}")
            except x509.ExtensionNotFound:
                print(f"{label} AKI absent")
        else:
            crl = x509.load_pem_x509_crl(pem)
            aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            num = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            print(f"{label} AKI {aki.key_identifier.hex() if aki.key_identifier else None} crlNumber={num}")
            print(f"{label} last={crl.last_update_utc.isoformat()} next={crl.next_update_utc}")

    dump("CA", ca_cert, "cert")
    dump("client", client_cert, "cert")
    dump("server", server_cert, "cert")
    dump("CRL", crl_pem, "crl")
    ca_obj = x509.load_pem_x509_certificate(ca_cert)
    ca_ski = ca_obj.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    leaf_aki = x509.load_pem_x509_certificate(client_cert).extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    crl_aki = x509.load_pem_x509_crl(crl_pem).extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    print(f"AKI match leaf==CA.SKI {leaf_aki == ca_ski} crl==CA.SKI {crl_aki == ca_ski}")

    # --- leading-dot permit rewritten to include apex ---
    section("leading-dot permit includes apex")
    try:
        dot_ca, dot_key = generate_ca_certificate("Dot CA", key_size=2048, permitted_subtrees=[".example.com"])
    except Exception as exc:  # noqa: BLE001
        print(f"leading-dot permit rejected: {exc}")
    else:
        dot_obj = x509.load_pem_x509_certificate(dot_ca)
        dot_constraints = dot_obj.extensions.get_extension_for_class(x509.NameConstraints).value
        print(f"stored permitted {list(dot_constraints.permitted_subtrees or [])}")
        try:
            generate_server_certificate(dot_ca, dot_key, "example.com", ["example.com"], key_size=2048)
            print("apex example.com ISSUED")
        except Exception as exc:  # noqa: BLE001
            print(f"apex rejected: {exc}")

    # --- IP-only constraint still allows a public DNS SAN (noninteractive CN add) ---
    section("IP-only CA issues public DNS name")
    ip_ca, ip_key = generate_ca_certificate("IP CA", key_size=2048, permitted_subtrees=["192.168.0.0/16"])
    try:
        pem, _ = generate_server_certificate(
            ip_ca, ip_key, "google.com", ["192.168.1.10"], key_size=2048, include_common_name_in_sans=True
        )
        sans = x509.load_pem_x509_certificate(pem).extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        print(f"ISSUED SANs {list(sans)}")
    except Exception as exc:  # noqa: BLE001
        print(f"rejected: {type(exc).__name__}: {exc}")

    # noninteractive CLI (stdin not a tty) auto-adds CN
    store = root / "ipstore"
    proc = run_cli(store, "init", "--cn", "IP CA", "--key-size", "2048", "--permit", "192.168.0.0/16")
    print(f"init rc={proc.returncode} {proc.stderr.strip()}")
    proc = run_cli(store, "create", "server", "google.com", "--san", "192.168.1.10", "--key-size", "2048")
    print(f"create rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}")

    # --- CN outside constraint, SAN inside, OpenSSL chain build ---
    section("CN outside constraint with in-constraint SAN")
    constrained, ckey = generate_ca_certificate("C", key_size=2048, permitted_subtrees=["home", "192.168.0.0/16"])
    try:
        leaf, _ = generate_server_certificate(
            constrained,
            ckey,
            "evil.com",
            ["api.home"],
            key_size=2048,
            include_common_name_in_sans=False,
        )
        print("library ISSUED leaf with CN evil.com SAN api.home")
    except Exception as exc:  # noqa: BLE001
        leaf = b""
        print(f"library rejected: {exc}")
    if leaf:
        ca_path = root / "c.crt"
        leaf_path = root / "leaf.crt"
        ca_path.write_bytes(constrained)
        leaf_path.write_bytes(leaf)
        print(openssl_verify(ca_path, leaf_path))

    # --- identity: CN equal to another serial ---
    section("CN collides with another serial")
    id_store = root / "idstore"
    proc = run_cli(id_store, "init", "--cn", "ID CA", "--key-size", "2048")
    print("init", proc.returncode, proc.stderr.strip())
    proc = run_cli(id_store, "create", "client", "alice", "--key-size", "2048")
    print(proc.stdout)
    cst = CertificateStore(id_store)
    alice = cst.get_certificate("alice")
    assert alice is not None
    serial_hex = alice.serial_number
    proc = run_cli(id_store, "create", "client", serial_hex, "--key-size", "2048")
    print(f"create CN=serial rc={proc.returncode} {proc.stdout} {proc.stderr}")
    proc = run_cli(id_store, "revoke", serial_hex)
    print(f"revoke {serial_hex!r} rc={proc.returncode} stdout={proc.stdout} stderr={proc.stderr}")
    cst = CertificateStore(id_store)
    for entry in cst.list_certificates(status="all"):
        print(
            f"  cn={entry.common_name!r} serial={entry.serial_number} revoked={entry.revoked_at is not None}"
        )
    # which one is still active?
    active = [e.common_name for e in cst.list_certificates(status="active")]
    print(f"still active: {active}")

    # --- delete --force drops revocation ---
    section("delete --force omits serial from CRL")
    dstore = root / "dstore"
    run_cli(dstore, "init", "--cn", "D CA", "--key-size", "2048")
    run_cli(dstore, "create", "client", "bob", "--key-size", "2048")
    dst = CertificateStore(dstore)
    bob = dst.get_certificate("bob")
    assert bob is not None
    bob_serial = int(bob.serial_number, 16)
    exported = root / "bob-exported.crt"
    exported.write_bytes(dst.read_certificate_pem(bob))
    ca_file = root / "d-ca.crt"
    ca_file.write_bytes(dst.read_ca()[0])
    proc = run_cli(dstore, "delete", "bob", "--force")
    print(f"delete --force rc={proc.returncode} {proc.stdout} {proc.stderr}")
    dst = CertificateStore(dstore)
    crl_path = dst.crl_path
    print("index entries", [(e.common_name, e.revoked_at, e.serial_number) for e in dst._read_index()])
    text = subprocess.run(["openssl", "crl", "-in", str(crl_path), "-noout", "-text"], text=True, capture_output=True)
    print(text.stdout)
    print("verify exported bob against post-delete CRL:", openssl_verify(ca_file, exported, crl_path))

    # compare with revoke
    run_cli(dstore, "create", "client", "carol", "--key-size", "2048")
    dst = CertificateStore(dstore)
    carol = dst.get_certificate("carol")
    assert carol is not None
    carol_pem = root / "carol.crt"
    carol_pem.write_bytes(dst.read_certificate_pem(carol))
    run_cli(dstore, "revoke", "carol")
    print("verify carol after revoke:", openssl_verify(ca_file, carol_pem, CertificateStore(dstore).crl_path))

    # --- CRL rollback: check stays green ---
    section("CRL rollback vs tiny-pki check")
    rstore = root / "rstore"
    run_cli(rstore, "init", "--cn", "R CA", "--key-size", "2048")
    run_cli(rstore, "create", "client", "dave", "--key-size", "2048")
    rst = CertificateStore(rstore)
    old_crl = rst.read_crl()
    assert old_crl is not None
    saved = root / "old-crl.pem"
    saved.write_bytes(old_crl)
    run_cli(rstore, "revoke", "dave")
    dave = None
    # dave is revoked; export was not saved. read cert before... files may still exist until delete.
    rst = CertificateStore(rstore)
    # revoked entries keep cert_path
    dave_entry = next(e for e in rst._read_index() if e.common_name == "dave")
    dave_cert_path = root / "dave.crt"
    dave_cert_path.write_bytes(rst.read_certificate_pem(dave_entry))
    fresh = openssl_verify(rst.ca_cert_path, dave_cert_path, rst.crl_path)
    print("after revoke, openssl:", fresh)
    proc = run_cli(rstore, "check", "--within", "0")
    print(f"check after revoke rc={proc.returncode}\n{proc.stdout}")
    # roll CRL back to the pre-revoke CRL (still within nextUpdate)
    rst.crl_path.write_bytes(saved.read_bytes())
    proc = run_cli(rstore, "check", "--within", "0")
    print(f"check after CRL rollback rc={proc.returncode}\n{proc.stdout}{proc.stderr}")
    proc = run_cli(rstore, "check", "--within", "0", "--include-revoked")
    print(f"check --include-revoked after rollback rc={proc.returncode}\n{proc.stdout}")
    print("openssl after rollback:", openssl_verify(rst.ca_cert_path, dave_cert_path, rst.crl_path))

    # expired CRL treated as authoritative for "not revoked"
    section("expired CRL still proves non-revocation")
    ca_pem, ca_key_pem = rst.read_ca()
    from tiny_pki._rsa import load_rsa_private_key

    key = load_rsa_private_key(ca_key_pem)
    ca_parsed = x509.load_pem_x509_certificate(ca_pem)
    now = datetime.now(UTC)
    stale = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_parsed.subject)
        .last_update(now - timedelta(days=10))
        .next_update(now - timedelta(days=1))
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    # a live cert not on that CRL
    live_pem, _ = generate_client_certificate(ca_pem, ca_key_pem, "erin", key_size=2048)
    status = check_certificate(live_pem, ca_cert_pem=ca_pem, crl_pem=stale)
    print(f"check_certificate against expired empty CRL: status={status.status} reasons={status.reasons}")
    rst.crl_path.write_bytes(stale)
    # erin is not in the store; check the store's remaining active certs (none) plus crl
    proc = run_cli(rstore, "check", "--kind", "client", "--within", "0")
    print(f"store check --kind client with expired CRL rc={proc.returncode}\n{proc.stdout}{proc.stderr}")
    proc = run_cli(rstore, "check", "--within", "0")
    print(f"store check all kinds rc={proc.returncode}\n{proc.stdout}")

    # --- export follows symlink ---
    section("export pem follows symlink")
    estore = root / "estore"
    run_cli(estore, "init", "--cn", "E CA", "--key-size", "2048")
    run_cli(estore, "create", "client", "alice", "--key-size", "2048")
    loot_dir = root / "loot"
    loot_dir.mkdir()
    loot = loot_dir / "stolen.pem"
    loot.write_bytes(b"PLACEHOLDER")
    os.chmod(loot, 0o666)
    cwd = root / "cwd"
    cwd.mkdir()
    link = cwd / "alice.pem"
    link.symlink_to(loot)
    proc = subprocess.run(
        ["uv", "run", "tiny-pki", "--store", str(estore), "--color", "never", "export", "pem", "alice"],
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    print(f"export rc={proc.returncode} stdout={proc.stdout} stderr={proc.stderr}")
    data = loot.read_bytes()
    print(f"loot size={len(data)} has PRIVATE KEY={'PRIVATE KEY' in data.decode(errors='replace')}")
    print(f"link is symlink? {link.is_symlink()} loot mode={oct(loot.stat().st_mode & 0o777)}")

    # --- in-store symlink on bundle write overwrites ca.key ---
    section("write_bundle follows in-store symlink onto ca.key")
    bst = CertificateStore(estore)
    entry = bst.get_certificate("alice")
    assert entry is not None
    key_before = bst.ca_key_path.read_bytes()
    bundle_name = f"bundles/{entry.common_name}-{entry.serial_number}.p12"
    # remove if a previous bundle exists; plant symlink to ca.key
    target_link = bst.root / bundle_name
    if target_link.exists() or target_link.is_symlink():
        target_link.unlink()
    target_link.symlink_to(bst.ca_key_path)
    try:
        bst.write_bundle(entry.common_name, b"NOT-A-KEY", serial_number=entry.serial_number)
        print("write_bundle succeeded")
    except Exception as exc:  # noqa: BLE001
        print(f"write_bundle raised {type(exc).__name__}: {exc}")
    key_after = bst.ca_key_path.read_bytes()
    print(f"ca.key overwritten={key_before != key_after} now_startswith={key_after[:20]!r}")

    # predictable serial leaf symlink
    section("add_certificate in-root cert symlink overwrites ca.key")
    sstore = CertificateStore(root / "sstore")
    sca, skey = generate_ca_certificate("S", key_size=2048)
    sstore.write_ca(sca, skey)
    original = sstore.ca_key_path.read_bytes()
    sstore.clients_dir.mkdir(exist_ok=True)
    (sstore.clients_dir / "alice-1.crt").symlink_to(sstore.ca_key_path)
    try:
        sstore.add_certificate(
            common_name="alice",
            kind="client",
            serial_number=1,
            cert_pem=b"CERTDATA",
            key_pem=b"KEYDATA",
            not_valid_after=datetime(2099, 1, 1, tzinfo=UTC),
            fingerprint="f",
        )
        print("add_certificate succeeded")
    except Exception as exc:  # noqa: BLE001
        print(f"add_certificate raised {type(exc).__name__}: {exc}")
    print(f"ca.key changed={sstore.ca_key_path.read_bytes() != original} content={sstore.ca_key_path.read_bytes()[:20]!r}")

    # --- store modes ---
    section("store modes")
    m = CertificateStore(root / "modestore")
    mca, mkey = generate_ca_certificate("M", key_size=2048)
    m.write_ca(mca, mkey)
    m.write_crl(generate_crl(mca, mkey, []))

    def mode(path: Path) -> str:
        return oct(path.stat().st_mode & 0o777)

    print(
        f"umask={oct(os.umask(0o022))} root={mode(m.root)} ca={mode(m.ca_dir)} "
        f"crt={mode(m.ca_cert_path)} key={mode(m.ca_key_path)} crl={mode(m.crl_path)} index={mode(m.index_path)}"
    )
    # restore umask was printed after changing it — fix by reading current. The call above SET umask to 022.
    # Re-create under umask 0.
    os.umask(0)
    z = CertificateStore(root / "umask0")
    z.write_ca(*generate_ca_certificate("Z", key_size=2048))
    print(
        f"umask0 root={mode(z.root)} key={mode(z.ca_key_path)} index={mode(z.index_path)} dir_writable_other="
        f"{bool(z.root.stat().st_mode & stat.S_IWOTH)}"
    )
    os.umask(0o022)

    # --- index key_path points at ca.key ---
    section("tampered index exports CA key")
    tstore = root / "tstore"
    run_cli(tstore, "init", "--cn", "T", "--key-size", "2048")
    run_cli(tstore, "create", "client", "alice", "--key-size", "2048")
    tst = CertificateStore(tstore)
    idx = json.loads(tst.index_path.read_text())
    idx[0]["key_path"] = "ca/ca.key"
    tst.index_path.write_text(json.dumps(idx))
    out = root / "exported.pem"
    proc = run_cli(tstore, "export", "pem", "alice", "--out", str(out))
    print(f"export rc={proc.returncode} {proc.stderr}")
    body = out.read_text(errors="replace") if out.exists() else ""
    ca_key_text = tst.ca_key_path.read_text()
    print(f"export contains CA private key={ca_key_text in body}")

    # --- huge validity ---
    section("huge validity_days")
    try:
        generate_ca_certificate("X", key_size=2048, validity_days=10**12)
        print("issued")
    except Exception as exc:  # noqa: BLE001
        print(f"{type(exc).__name__}: {exc}")

    # --- pkcs12 algorithms ---
    section("pkcs12")
    p12 = generate_pkcs12(client_cert, client_key, ca_cert, "alice", b"change-me-to-a-long-random-password")
    p12_path = root / "a.p12"
    p12_path.write_bytes(p12)
    info = subprocess.run(
        ["openssl", "pkcs12", "-in", str(p12_path), "-info", "-noout", "-passin", "pass:change-me-to-a-long-random-password"],
        text=True,
        capture_output=True,
    )
    print(info.stdout)
    print(info.stderr)
    legacy = generate_pkcs12(
        client_cert, client_key, ca_cert, "alice", b"change-me-to-a-long-random-password", legacy=True
    )
    leg_path = root / "a-legacy.p12"
    leg_path.write_bytes(legacy)
    info = subprocess.run(
        ["openssl", "pkcs12", "-in", str(leg_path), "-info", "-noout", "-passin", "pass:change-me-to-a-long-random-password"],
        text=True,
        capture_output=True,
    )
    print("LEGACY", info.stderr)

    # wrong password / key inspect errors
    section("error text")
    proc = subprocess.run(
        ["uv", "run", "tiny-pki", "--color", "never", "inspect", str(tst.ca_key_path)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    print(f"inspect key rc={proc.returncode} stderr={proc.stderr[:500]!r}")
    print(f"stderr contains key bytes={ca_key_text[:40] in proc.stderr}")

    # git sha injection
    section("TINY_PKI_GIT_SHA")
    proc = subprocess.run(
        ["uv", "run", "tiny-pki", "--version"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        env={**os.environ, "TINY_PKI_GIT_SHA": "abc\nEVIL injected line"},
    )
    print(repr(proc.stdout))

    # IPv4-mapped vs excluded IPv4
    section("ipv4-mapped vs excluded network")
    # build external CA: permitted 0.0.0.0/0 and ::/0, excluded 10.0.0.0/8
    from tiny_pki._rsa import load_rsa_private_key as load_key

    base_ca, base_key = generate_ca_certificate("B", key_size=2048)
    k = load_key(base_key)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Excl CA")])
    now = datetime.now(UTC)
    excl = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(k.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.IPAddress(__import__("ipaddress").ip_network("0.0.0.0/0")),
                    x509.IPAddress(__import__("ipaddress").ip_network("::/0")),
                    x509.DNSName("example"),
                ],
                excluded_subtrees=[x509.IPAddress(__import__("ipaddress").ip_network("10.0.0.0/8"))],
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
        .sign(k, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    for san in ("10.1.2.3", "::ffff:10.1.2.3", "192.0.2.1"):
        try:
            generate_server_certificate(excl, base_key, "n.example", [san], key_size=2048, include_common_name_in_sans=False)
            print(f"SAN {san} ISSUED")
        except Exception as exc:  # noqa: BLE001
            print(f"SAN {san} rejected: {exc}")

    print("\nDONE")


if __name__ == "__main__":
    main_repro()
