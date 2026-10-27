from app.policy import decide

TAU = 0.385


def test_low_score_is_safe():
    assert decide(0.01, TAU)["verdict"] == "SAFE"


def test_high_score_is_phishing():
    assert decide(0.9, TAU)["verdict"] == "PHISHING"


def test_warning_band():
    assert decide(0.30, TAU)["verdict"] == "SUSPICIOUS"


def test_virustotal_overrides_low_ml_score():
    vt = {"found": True, "malicious": 5, "suspicious": 0}
    assert decide(0.02, TAU, vt=vt)["verdict"] == "PHISHING"


def test_new_domain_escalates_one_level():
    assert decide(0.02, TAU, whois={"age_days": 3})["verdict"] == "SUSPICIOUS"
    assert decide(0.30, TAU, whois={"age_days": 3})["verdict"] == "PHISHING"


def test_old_domain_does_not_escalate():
    assert decide(0.02, TAU, whois={"age_days": 4000})["verdict"] == "SAFE"


def test_failed_lookups_never_crash():
    r = decide(0.02, TAU, dns={"error": "timeout"}, whois={"error": "timeout"},
               vt={"enabled": True, "found": False, "error": "timeout"})
    assert r["verdict"] == "SAFE"
