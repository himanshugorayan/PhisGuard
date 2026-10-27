import datetime as dt

from app.whois_check import _earliest


def test_mixed_timezone_dates_do_not_crash():
    aware = dt.datetime(1997, 9, 15, 4, 0, tzinfo=dt.timezone.utc)
    naive = dt.datetime(1997, 9, 15, 7, 0)
    assert _earliest([naive, aware]).year == 1997
