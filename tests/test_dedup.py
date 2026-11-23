"""Tests de deduplicacion de hallazgos."""
from bbhunter.findings import dedup_hash


def test_same_finding_same_hash():
    a = dedup_hash("prog", "xss_reflected", "tid", "https://x.com/search?q=1", "q")
    b = dedup_hash("prog", "xss_reflected", "tid", "https://x.com/search?q=2", "q")
    # La query no debe influir: mismo endpoint + parametro => mismo hash
    assert a == b


def test_trailing_slash_normalized():
    a = dedup_hash("prog", "exposure", "tid", "https://x.com/.env", "")
    b = dedup_hash("prog", "exposure", "tid", "https://x.com/.env/", "")
    assert a == b


def test_different_param_different_hash():
    a = dedup_hash("prog", "xss_reflected", "tid", "https://x.com/s", "q")
    b = dedup_hash("prog", "xss_reflected", "tid", "https://x.com/s", "search")
    assert a != b


def test_different_host_different_hash():
    a = dedup_hash("prog", "exposure", "tid", "https://a.com/.env", "")
    b = dedup_hash("prog", "exposure", "tid", "https://b.com/.env", "")
    assert a != b


def test_hash_is_short_and_stable():
    h = dedup_hash("prog", "exposure", "tid", "https://a.com/.env", "")
    assert len(h) == 20
    assert h == dedup_hash("prog", "exposure", "tid", "https://a.com/.env", "")
