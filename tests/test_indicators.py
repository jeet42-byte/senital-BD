import pytest

from sentinel.indicators import IndicatorType as T
from sentinel.indicators import guess_type, normalize, refang


def test_refang():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1.2.3(.)4") == "1.2.3.4"


@pytest.mark.parametrize(
    "kind,raw,expected",
    [
        (T.IPV4, "185.220.101.45", "185.220.101.45"),
        (T.IPV4, "185.220.101.45:443", "185.220.101.45"),
        (T.IPV4, "192.168.1.1", None),     # private
        (T.IPV4, "127.0.0.1", None),       # loopback
        (T.IPV4, "999.1.1.1", None),
        (T.DOMAIN, "Evil[.]COM.", "evil.com"),
        (T.DOMAIN, "*.evil.com", "evil.com"),
        (T.DOMAIN, "no-tld", None),
        (T.DOMAIN, "-bad-.com", None),
        (T.DOMAIN, "1.2.3.4", None),
        (T.DOMAIN, "bücher.de", "xn--bcher-kva.de"),
        (T.URL, "HXXP://Evil[.]com/Path?a=1#frag", "http://evil.com/Path?a=1"),
        (T.URL, "evil.com/x", "http://evil.com/x"),
        (T.URL, "http://evil.com", "http://evil.com/"),
        (T.URL, "http://192.168.0.5/a.sh", None),  # private host
        (T.URL, "javascript:alert(1)", None),
        (T.URL, "not a url at all", None),
        (T.SHA256, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (T.MD5, "abc", None),
    ],
)
def test_normalize(kind, raw, expected):
    assert normalize(kind, raw) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.4.4", T.IPV4),
        ("1.2.3.4:80", T.IPV4),
        ("evil.com", T.DOMAIN),
        ("hxxp://evil[.]com/x", T.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", T.MD5),
        ("a" * 64, T.SHA256),
        ("???", None),
    ],
)
def test_guess_type(value, expected):
    assert guess_type(value) == expected


def test_overlong_urls_are_rejected():
    assert normalize(T.URL, "http://evil.com/" + "a" * 3000) is None


def test_postgres_urls_get_a_driver():
    from sentinel.db import _with_driver

    assert _with_driver("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert _with_driver("postgresql://u:p@h/db?sslmode=require") == "postgresql+psycopg://u:p@h/db?sslmode=require"
    assert _with_driver("sqlite:///x.db") == "sqlite:///x.db"
