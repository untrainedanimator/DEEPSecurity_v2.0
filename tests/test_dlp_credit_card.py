"""Tests for the v2.5 Luhn-validated `credit_card` DLP pattern."""

from __future__ import annotations

from deepsecurity.dlp import _luhn_valid, scan_text

# Real-format test PANs that pass the Luhn check (NEVER real cards).
VISA_OK = "4242 4242 4242 4242"  # canonical Stripe test Visa
MC_OK = "5555 5555 5555 4444"
AMEX_OK = "3782 822463 10005"
DISCOVER_OK = "6011 1111 1111 1117"


def test_luhn_validates_known_test_pans() -> None:
    assert _luhn_valid("4242424242424242") is True
    assert _luhn_valid("5555555555554444") is True
    assert _luhn_valid("378282246310005") is True
    assert _luhn_valid("6011111111111117") is True


def test_luhn_rejects_random_16_digit() -> None:
    assert _luhn_valid("1234567890123456") is False


def test_credit_card_match_visa() -> None:
    findings = scan_text(f"card: {VISA_OK}", "/x/notes.txt")
    names = {f.pattern_name for f in findings}
    assert "credit_card" in names


def test_credit_card_match_mc() -> None:
    findings = scan_text(f"card: {MC_OK}", "/x/notes.txt")
    assert any(f.pattern_name == "credit_card" for f in findings)


def test_credit_card_match_amex() -> None:
    findings = scan_text(f"card: {AMEX_OK}", "/x/notes.txt")
    assert any(f.pattern_name == "credit_card" for f in findings)


def test_credit_card_match_discover() -> None:
    findings = scan_text(f"card: {DISCOVER_OK}", "/x/notes.txt")
    assert any(f.pattern_name == "credit_card" for f in findings)


def test_credit_card_no_match_on_random_digits() -> None:
    findings = scan_text("card: 4111 1111 1111 1112", "/x/notes.txt")
    # The shape is correct (Visa-like) but Luhn fails — must be dropped.
    assert not any(f.pattern_name == "credit_card" for f in findings)


def test_credit_card_no_match_on_timestamp_like_run() -> None:
    findings = scan_text("ts=1234567890123456", "/x/notes.txt")
    assert not any(f.pattern_name == "credit_card" for f in findings)


def test_credit_card_redacts_payload() -> None:
    findings = [
        f for f in scan_text(f"pan: {VISA_OK}", "/x/notes.txt") if f.pattern_name == "credit_card"
    ]
    assert findings, "expected the Luhn-valid Visa to match"
    assert "4242" not in findings[0].redacted_preview
    assert "****" in findings[0].redacted_preview


def test_credit_card_severity_is_high() -> None:
    findings = [
        f for f in scan_text(f"pan: {VISA_OK}", "/x/notes.txt") if f.pattern_name == "credit_card"
    ]
    assert findings[0].severity == "high"
