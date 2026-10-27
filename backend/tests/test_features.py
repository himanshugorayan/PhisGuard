import pytest

from app.features import FEATURE_COLS, extract_features, parse_target


def test_all_model_columns_are_produced():
    f = extract_features("https://www.example.com/a?b=1&c=2")
    assert set(FEATURE_COLS) <= set(f)


def test_ip_detection():
    assert extract_features("http://192.168.1.5/login")["IsDomainIP"] == 1


def test_obfuscation_counted():
    assert extract_features("http://a.com/%41%42")["NoOfObfuscatedChar"] == 2


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x.com", "http://localhost", "not a url"])
def test_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        parse_target(bad)
