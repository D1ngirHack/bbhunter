"""Tests del gate de scope: el control de seguridad mas importante."""
from bbhunter.scope import Scope, ScopeRules


def make_scope():
    return Scope(
        program="t",
        in_scope=["*.ejemplo.com", "ejemplo.com", "api.otra.com"],
        out_of_scope=["blog.ejemplo.com", "*.dev.ejemplo.com"],
        rules=ScopeRules(),
    )


def test_apex_in_scope():
    assert make_scope().is_allowed("ejemplo.com")
    assert make_scope().is_allowed("https://ejemplo.com/ruta?x=1")


def test_wildcard_subdomain_in_scope():
    assert make_scope().is_allowed("https://www.ejemplo.com")
    assert make_scope().is_allowed("a.b.ejemplo.com")


def test_exact_host_in_scope():
    assert make_scope().is_allowed("https://api.otra.com/v1")


def test_out_of_scope_wins_over_in_scope():
    # blog.ejemplo.com casa con *.ejemplo.com pero esta excluido explicitamente
    assert not make_scope().is_allowed("https://blog.ejemplo.com")
    assert not make_scope().is_allowed("https://foo.dev.ejemplo.com")


def test_unrelated_domain_rejected():
    assert not make_scope().is_allowed("https://evil.com")
    assert not make_scope().is_allowed("https://ejemplo.com.evil.com")  # no debe colar


def test_empty_or_invalid_rejected():
    assert not make_scope().is_allowed("")
    assert not make_scope().is_allowed("   ")


def test_filter_allowed_splits_correctly():
    scope = make_scope()
    allowed, rejected = scope.filter_allowed([
        "https://www.ejemplo.com", "https://blog.ejemplo.com", "https://evil.com",
    ])
    assert "https://www.ejemplo.com" in allowed
    assert "https://blog.ejemplo.com" in rejected
    assert "https://evil.com" in rejected


def test_effective_rate_limit_capped():
    scope = Scope(program="t", in_scope=["ejemplo.com"], rules=ScopeRules(rate_limit_rps=100))
    assert scope.effective_rate_limit(10) == 10   # el tope global manda
    scope2 = Scope(program="t", in_scope=["ejemplo.com"], rules=ScopeRules(rate_limit_rps=3))
    assert scope2.effective_rate_limit(10) == 3
