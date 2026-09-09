from detector import analyze_url


def test_safe_https_url_has_low_score():
    report = analyze_url("https://example.com")
    assert report["score"] == 0
    assert report["classification"] == "Likely Safe"


def test_warning_signals_raise_score():
    report = analyze_url("http://198.51.100.24/login-verify-account-123")
    assert report["score"] >= 61
    assert report["classification"] == "Potential Phishing"
    assert any(check["name"] == "IP address host" and check["status"] == "warning" for check in report["checks"])


def test_missing_scheme_is_rejected():
    try:
        analyze_url("example.com")
    except ValueError as error:
        assert "scheme" in str(error)
    else:
        raise AssertionError("A URL without a scheme should be rejected")
