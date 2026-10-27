from app.brand_check import brand_lookalike as bl


def test_lookalikes_are_flagged():
    assert bl("www.paaypaal.com", "paaypaal.com")["brand"] == "paypal"
    assert bl("www.starbuck.com", "starbuck.com")["brand"] == "starbucks"
    assert bl("goggle.com", "goggle.com")["brand"] == "google"


def test_brand_in_subdomain_or_hyphenated_name():
    assert bl("paypal-secure-login.verify-account.xyz", "verify-account.xyz")["kind"] == "embedded"
    assert bl("paypal.com.evil.xyz", "evil.xyz")["where"] == "subdomain"
    assert bl("amazon-verify.top", "amazon-verify.top")["brand"] == "amazon"


def test_official_and_unrelated_domains_pass():
    for host, dom in [("www.google.com", "google.com"), ("mail.google.com", "google.com"),
                      ("www.bjhdv.com", "bjhdv.com"), ("example.com", "example.com"),
                      ("login.microsoftonline.com", "microsoftonline.com")]:
        assert bl(host, dom) is None
