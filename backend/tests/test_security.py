"""
Tests de seguridad para PhishingScanner — SSRF, validaciones y heurísticas.
Ejecutar desde backend/ con: pytest tests/test_security.py -v --no-cov
"""
import pytest

from services.utils import (
    is_safe_url,
    is_safe_url_async,
    levenshtein_distance,
    levenshtein_similarity,
)

# ────────────────────────────────────────────────────────────────────────────
# is_safe_url — protección SSRF (versión síncrona)
# ────────────────────────────────────────────────────────────────────────────

class TestIsSafeUrl:
    def test_blocks_localhost_ip(self):
        assert is_safe_url("http://127.0.0.1/admin") is False

    def test_blocks_localhost_hostname(self):
        assert is_safe_url("http://localhost:8080") is False

    def test_blocks_private_192(self):
        assert is_safe_url("http://192.168.1.1") is False

    def test_blocks_private_10(self):
        assert is_safe_url("http://10.0.0.1") is False

    def test_blocks_private_172(self):
        assert is_safe_url("http://172.16.0.1") is False

    def test_blocks_link_local_aws_metadata(self):
        assert is_safe_url("http://169.254.169.254") is False

    def test_blocks_javascript_scheme(self):
        assert is_safe_url("javascript:alert(1)") is False

    def test_blocks_file_scheme(self):
        assert is_safe_url("file:///etc/passwd") is False

    def test_blocks_empty_string(self):
        assert is_safe_url("") is False

    def test_blocks_none(self):
        assert is_safe_url(None) is False  # type: ignore

    def test_blocks_too_long_hostname(self):
        assert is_safe_url("http://" + "a" * 300 + ".com") is False

    def test_allows_google(self):
        assert is_safe_url("https://www.google.com") is True

    def test_allows_public_http(self):
        assert is_safe_url("http://example.com") is True

    def test_allows_github(self):
        assert is_safe_url("https://github.com") is True


# ────────────────────────────────────────────────────────────────────────────
# is_safe_url_async — mismas garantías sin bloquear el event loop
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestIsSafeUrlAsync:
    async def test_blocks_localhost(self):
        assert await is_safe_url_async("http://127.0.0.1") is False

    async def test_blocks_private(self):
        assert await is_safe_url_async("http://192.168.0.1") is False

    async def test_allows_public(self):
        assert await is_safe_url_async("https://www.google.com") is True


# ────────────────────────────────────────────────────────────────────────────
# levenshtein — detección de typosquatting
# ────────────────────────────────────────────────────────────────────────────

class TestLevenshteinDistance:
    def test_identical(self):
        assert levenshtein_distance("paypal", "paypal") == 0

    def test_insertion(self):
        assert levenshtein_distance("paypal", "paypall") == 1

    def test_deletion(self):
        assert levenshtein_distance("paypal", "paypa") == 1

    def test_substitution(self):
        assert levenshtein_distance("paypal", "paypa1") == 1

    def test_empty(self):
        assert levenshtein_distance("", "") == 0

    def test_one_empty(self):
        assert levenshtein_distance("abc", "") == 3

    def test_commutative(self):
        assert levenshtein_distance("google", "gooogle") == levenshtein_distance("gooogle", "google")


class TestLevenshteinSimilarity:
    def test_identical(self):
        assert levenshtein_similarity("paypal", "paypal") == pytest.approx(1.0)

    def test_close_strings_high_sim(self):
        assert levenshtein_similarity("paypal", "paypa1") >= 0.80

    def test_different_strings_low_sim(self):
        assert levenshtein_similarity("google", "amazon") < 0.50

    def test_both_empty(self):
        assert levenshtein_similarity("", "") == pytest.approx(1.0)


# ────────────────────────────────────────────────────────────────────────────
# Hostname validation — whois_scanner
# ────────────────────────────────────────────────────────────────────────────

class TestWhoisHostnameValidation:
    def _validate(self, hostname):
        from services.scanners.whois_scanner import _validate_hostname
        return _validate_hostname(hostname)

    def test_rejects_private_ip(self):
        with pytest.raises(ValueError, match="WHOIS no acepta IPs"):
            self._validate("192.168.1.1")

    def test_rejects_public_ip(self):
        with pytest.raises(ValueError, match="WHOIS no acepta IPs"):
            self._validate("8.8.8.8")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            self._validate("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="largo"):
            self._validate("a" * 300 + ".com")

    def test_accepts_valid(self):
        assert self._validate("google.com") == "google.com"

    def test_normalizes_lowercase(self):
        assert self._validate("Google.COM") == "google.com"


# ────────────────────────────────────────────────────────────────────────────
# resolve_redirect_chain — resolución segura de redirecciones
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestResolveRedirectChain:
    async def test_resolve_no_redirect(self, monkeypatch):
        from services.utils import resolve_redirect_chain
        import httpx

        async def mock_is_safe_url_async(url):
            return True
        monkeypatch.setattr("services.utils.is_safe_url_async", mock_is_safe_url_async)

        class DummyResponse:
            def __init__(self):
                self.status_code = 200
                self.headers = {}

        class DummyClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            async def head(self, url, timeout):
                return DummyResponse()

        monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: DummyClient())

        chain = await resolve_redirect_chain("https://www.example.com")
        assert chain == ["https://www.example.com"]

    async def test_resolve_single_redirect(self, monkeypatch):
        from services.utils import resolve_redirect_chain
        import httpx

        async def mock_is_safe_url_async(url):
            return True
        monkeypatch.setattr("services.utils.is_safe_url_async", mock_is_safe_url_async)

        calls = []

        class DummyResponse:
            def __init__(self, status_code, headers):
                self.status_code = status_code
                self.headers = headers

        class DummyClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            async def head(self, url, timeout):
                calls.append(url)
                if url == "https://short.url":
                    return DummyResponse(301, {"location": "https://final.url"})
                return DummyResponse(200, {})

        monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: DummyClient())

        chain = await resolve_redirect_chain("https://short.url")
        assert chain == ["https://short.url", "https://final.url"]
        assert len(calls) == 2

    async def test_resolve_unsafe_redirect(self, monkeypatch):
        from services.utils import resolve_redirect_chain
        import httpx

        class DummyResponse:
            def __init__(self, status_code, headers):
                self.status_code = status_code
                self.headers = headers

        class DummyClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            async def head(self, url, timeout):
                return DummyResponse(301, {"location": "http://127.0.0.1/admin"})

        monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: DummyClient())

        chain = await resolve_redirect_chain("https://short.url")
        assert chain == ["https://short.url"]
