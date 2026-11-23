from datetime import timedelta

from sentinel.scoring import Evidence, compute_score, severity
from tests.conftest import NOW


def test_single_source_uses_its_reliability():
    assert compute_score("url", [Evidence("urlhaus")], NOW, False, NOW) == 85


def test_corroboration_raises_score():
    one = compute_score("url", [Evidence("urlhaus")], NOW, False, NOW)
    two = compute_score("url", [Evidence("urlhaus"), Evidence("openphish")], NOW, False, NOW)
    assert two == 96 and two > one


def test_source_confidence_scales_weight():
    assert compute_score("domain", [Evidence("threatfox", 50)], NOW, False, NOW) == 40


def test_ip_decays_with_a_two_week_half_life():
    assert compute_score("ipv4", [Evidence("feodotracker")], NOW - timedelta(days=14), False, NOW) == 45


def test_hashes_do_not_decay():
    old = NOW - timedelta(days=400)
    assert compute_score("sha256", [Evidence("threatfox", 100)], old, False, NOW) == 80


def test_bd_boost_and_cap():
    assert compute_score("url", [Evidence("urlhaus")], NOW, True, NOW) == 95
    assert compute_score("ipv4", [Evidence("feodotracker"), Evidence("threatfox")], NOW, True, NOW) == 100


def test_unknown_source_and_no_evidence():
    assert compute_score("url", [Evidence("somefeed")], NOW, False, NOW) == 50
    assert compute_score("url", [], NOW, True, NOW) == 0


def test_severity_bands():
    assert [severity(s) for s in (95, 80, 79, 50, 49)] == ["high", "high", "medium", "medium", "low"]
