import pytest
from services.scanners.geo_scanner import GeoScanner

class TestGeoScannerValidation:
    def test_validate_public_ip_ipv4(self):
        assert GeoScanner.validate_public_ip("8.8.8.8") == "8.8.8.8"
        assert GeoScanner.validate_public_ip("1.1.1.1") == "1.1.1.1"

    def test_validate_public_ip_ipv6(self):
        # Google Public DNS IPv6
        assert GeoScanner.validate_public_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    def test_rejects_private_ips(self):
        with pytest.raises(ValueError, match="no permitida"):
            GeoScanner.validate_public_ip("192.168.1.1")
        with pytest.raises(ValueError, match="no permitida"):
            GeoScanner.validate_public_ip("10.0.0.1")
        with pytest.raises(ValueError, match="no permitida"):
            GeoScanner.validate_public_ip("127.0.0.1")

    def test_rejects_invalid_strings(self):
        with pytest.raises(ValueError, match="inválida"):
            GeoScanner.validate_public_ip("not-an-ip")
        with pytest.raises(ValueError, match="vacía"):
            GeoScanner.validate_public_ip("")
        with pytest.raises(ValueError, match="vacía"):
            GeoScanner.validate_public_ip(None)

    def test_strips_whitespace(self):
        assert GeoScanner.validate_public_ip("  8.8.8.8  ") == "8.8.8.8"
