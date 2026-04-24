"""DLP regex engine — positive + negative cases, redaction, severity."""
from __future__ import annotations

from pathlib import Path

from deepsecurity.dlp import scan_file_for_secrets, scan_text


def test_detects_aws_access_key_id() -> None:
    hits = scan_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "/x.env")
    names = [h.pattern_name for h in hits]
    assert "aws_access_key_id" in names
    # Critical severity.
    assert any(h.severity == "critical" for h in hits if h.pattern_name == "aws_access_key_id")


def test_detects_private_key_pem() -> None:
    hits = scan_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n", "/x.pem")
    assert any(h.pattern_name == "private_key_pem" for h in hits)


def test_detects_huggingface_token() -> None:
    hits = scan_text('login("hf_fakeTokenForTestingPurposesOnly")', "/x.py")
    assert any(h.pattern_name == "huggingface_token" for h in hits)


def test_detects_github_pat() -> None:
    hits = scan_text("GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n", "/x.env")
    assert any(h.pattern_name == "github_pat" for h in hits)


def test_detects_jwt_token() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123xyz"
    hits = scan_text(f"Authorization: Bearer {jwt}\n", "/x.log")
    assert any(h.pattern_name == "jwt_token" for h in hits)


def test_detects_ssn_and_credit_card() -> None:
    text = "SSN: 123-45-6789  CC: 4111 1111 1111 1111\n"
    hits = scan_text(text, "/x.txt")
    names = {h.pattern_name for h in hits}
    assert "us_ssn" in names
    assert "credit_card_number" in names


def test_redaction_hides_the_secret() -> None:
    hits = scan_text("key=AKIAIOSFODNN7EXAMPLE\n", "/x.env")
    assert hits
    # The raw secret must not appear in the preview.
    for h in hits:
        assert "AKIAIOSFODNN7EXAMPLE" not in h.redacted_preview
        assert "****" in h.redacted_preview


def test_line_numbers_are_one_based() -> None:
    text = "line one\nline two\nAKIAIOSFODNN7EXAMPLE\n"
    hits = scan_text(text, "/x.env")
    aws = [h for h in hits if h.pattern_name == "aws_access_key_id"]
    assert aws
    assert aws[0].line_number == 3


def test_skips_media_files(tmp_path: Path) -> None:
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"AKIAIOSFODNN7EXAMPLE" * 100)  # even if it contains secret bytes
    assert scan_file_for_secrets(p, "image/jpeg") == []


def test_skips_large_files(tmp_path: Path) -> None:
    p = tmp_path / "big.txt"
    p.write_text("x" * (3 * 1024 * 1024))
    assert scan_file_for_secrets(p, "text/plain", max_bytes=1024 * 1024) == []


def test_scans_small_text_file(tmp_path: Path) -> None:
    p = tmp_path / "small.txt"
    p.write_text("mail me: someone@example.com\n")
    hits = scan_file_for_secrets(p, "text/plain")
    assert any(h.pattern_name == "email_address" for h in hits)


def test_regex_timeout_bails_on_redos_pattern(monkeypatch) -> None:
    """A catastrophically-backtracking pattern must not hang the scanner.

    Regression guard for the v2.3 audit finding: dlp.py used to call
    ``pat.regex.finditer(content)`` with no budget, so a pathological
    pattern like ``(a+)+$`` against a long input would pin the worker.
    Now each pattern runs in a thread with a join timeout; on expiry
    we log ``dlp.regex_timeout`` and skip the pattern for that file.

    Implementation note: we do NOT use a real ReDoS pattern here. Real
    catastrophic backtracking holds the GIL for tens of seconds and the
    daemon worker thread keeps burning CPU long after the test returns,
    starving the rest of pytest. Instead we stub the regex's
    ``finditer`` with a slow callable that sleeps — exercises the exact
    same timeout branch, but the worker thread exits quickly once its
    sleep ends. Same code path, bounded wall-clock, zero CPU burn.
    """
    import re
    import threading
    import time
    import types

    from deepsecurity import dlp

    # Build a fake Pattern object whose finditer() blocks on a sleep.
    # Blocking via time.sleep (not a busy loop) releases the GIL so it
    # doesn't wedge pytest's other tests.
    HANG_SECONDS = 3.0  # much longer than our test timeout → guaranteed to trip

    fake_pattern = types.SimpleNamespace()
    # Use an Event so we can also verify the worker genuinely started.
    started = threading.Event()

    def _slow_finditer(_text: str):
        started.set()
        time.sleep(HANG_SECONDS)
        return iter(())  # never reached within the test window

    fake_pattern.finditer = _slow_finditer

    evil = dlp.DLPPattern(
        name="ticking_bomb",
        regex=fake_pattern,  # type: ignore[arg-type]
        severity="low",
        context=10,
    )
    monkeypatch.setattr(dlp, "PATTERNS", [evil])

    # Shrink the per-pattern budget so the test is fast but still
    # exercises the timeout branch.
    monkeypatch.setattr(dlp, "DLP_REGEX_TIMEOUT_S", 0.2)

    t0 = time.monotonic()
    hits = dlp.scan_text("irrelevant content", "/tmp/nope")
    elapsed = time.monotonic() - t0

    # The worker thread MUST have actually started — otherwise the test
    # is a tautology (we'd be measuring the time to spawn a thread).
    assert started.wait(1.0), "worker thread never started; test is not exercising the timeout branch"

    # No hits (pattern timed out before matching), and wall-clock is
    # bounded by the timeout budget — not the pattern's worst case.
    assert hits == []
    assert elapsed < 1.0, (
        f"DLP took {elapsed:.2f}s — timeout not honoured; "
        "pathological regex is still free to hang the scanner"
    )
