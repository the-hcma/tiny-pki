"""README Python snippets must run as written (issue #10: newcomer path)."""

from __future__ import annotations

import re
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from hamcrest import (
    assert_that,
    contains_string,
    equal_to,
    greater_than_or_equal_to,
    has_length,
    matches_regexp,
    not_none,
)

_README = Path(__file__).resolve().parent.parent / "README.md"
_FINGERPRINT = r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$"
_PYTHON_BLOCK = re.compile(r"^```python\n(.*?)^```", re.MULTILINE | re.DOTALL)


def test_readme_links_consumer_issues() -> None:
    text = _README.read_text(encoding="utf-8")
    assert_that(text, contains_string("https://github.com/the-hcma/my-tracks/issues/1345"))
    assert_that(text, contains_string("https://github.com/the-hcma/home-warden/issues/49"))


def test_readme_python_blocks_execute() -> None:
    blocks = _python_blocks()
    assert_that(blocks, has_length(greater_than_or_equal_to(1)))
    for block in blocks:
        _run(block)


def test_readme_quick_start_issues_ca_leaves_crl_and_bundle() -> None:
    quick_start = [b for b in _python_blocks() if "generate_crl(" in b]
    assert_that(quick_start, has_length(1))
    namespace, stdout = _run(quick_start[0])

    assert_that(stdout.strip(), matches_regexp(_FINGERPRINT))

    ca_cert = x509.load_pem_x509_certificate(namespace["ca_cert"])
    crl = x509.load_pem_x509_crl(namespace["crl_pem"])
    assert_that(crl.is_signature_valid(ca_cert.public_key()), equal_to(True))  # type: ignore[arg-type]
    assert_that(crl.get_revoked_certificate_by_serial_number(namespace["serial"]), not_none())

    server_cert = x509.load_pem_x509_certificate(namespace["server_cert"])
    sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert_that(sans.get_values_for_type(x509.DNSName), equal_to(["api.home"]))

    key, cert, _ = pkcs12.load_key_and_certificates(namespace["p12"], b"change-me-to-a-long-random-password")
    assert_that(key, not_none())
    assert_that(cert, not_none())


def _python_blocks() -> list[str]:
    return _PYTHON_BLOCK.findall(_README.read_text(encoding="utf-8"))


def _run(block: str) -> tuple[dict[str, Any], str]:
    namespace: dict[str, Any] = {}
    out = StringIO()
    with redirect_stdout(out):
        exec(compile(block, str(_README), "exec"), namespace)  # noqa: S102
    return namespace, out.getvalue()
