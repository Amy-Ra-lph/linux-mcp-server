import jwt
import pytest

from linux_mcp_server.auth_spiffe import parse_spiffe_id
from linux_mcp_server.auth_spiffe import SPIFFETokenVerifier


class TestParseSpiffeId:
    def test_valid_spiffe_id(self):
        result = parse_spiffe_id("spiffe://example.org/workload/web", "example.org")
        assert result["spiffe_id"] == "spiffe://example.org/workload/web"
        assert result["trust_domain"] == "example.org"
        assert result["workload_path"] == "workload/web"
        assert result["role"] == "viewer"

    def test_admin_role_from_path(self):
        result = parse_spiffe_id("spiffe://example.org/ns/prod/admin", "example.org")
        assert result["role"] == "admin"

    def test_operator_role_from_path(self):
        result = parse_spiffe_id("spiffe://example.org/workload/operator", "example.org")
        assert result["role"] == "operator"

    def test_containment_role_from_path(self):
        result = parse_spiffe_id("spiffe://example.org/service/containment/agent", "example.org")
        assert result["role"] == "containment"

    def test_viewer_role_default(self):
        result = parse_spiffe_id("spiffe://example.org/service/monitoring", "example.org")
        assert result["role"] == "viewer"

    def test_trust_domain_mismatch_raises(self):
        with pytest.raises(ValueError, match="Trust domain mismatch"):
            parse_spiffe_id("spiffe://wrong.org/workload/web", "example.org")

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid SPIFFE ID format"):
            parse_spiffe_id("not-a-spiffe-id", "example.org")

    def test_missing_path_raises(self):
        with pytest.raises(ValueError, match="Invalid SPIFFE ID format"):
            parse_spiffe_id("spiffe://example.org", "example.org")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid SPIFFE ID format"):
            parse_spiffe_id("", "example.org")


def _make_jwt_svid(sub: str, aud: str | list[str] | None = None, scope: str | None = None) -> str:
    """Create an unsigned JWT-SVID for testing."""
    payload: dict = {"sub": sub}
    if aud is not None:
        payload["aud"] = aud
    if scope is not None:
        payload["scope"] = scope
    return jwt.encode(payload, "secret", algorithm="HS256")


class TestSPIFFETokenVerifier:
    @pytest.fixture()
    def verifier(self):
        return SPIFFETokenVerifier(
            trust_domain="example.org",
            workload_api_socket="unix:///tmp/spire-agent/public/api.sock",
            base_url="http://localhost:8000",
        )

    @pytest.fixture()
    def verifier_with_audience(self):
        return SPIFFETokenVerifier(
            trust_domain="example.org",
            workload_api_socket="unix:///tmp/spire-agent/public/api.sock",
            audience="linux-mcp",
            base_url="http://localhost:8000",
        )

    async def test_valid_jwt_svid(self, verifier):
        token = _make_jwt_svid("spiffe://example.org/workload/web")
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.client_id == "spiffe://example.org/workload/web"
        assert result.subject == "spiffe://example.org/workload/web"
        assert result.claims["role"] == "viewer"
        assert result.claims["trust_domain"] == "example.org"

    async def test_admin_role_in_claims(self, verifier):
        token = _make_jwt_svid("spiffe://example.org/ns/prod/admin")
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.claims["role"] == "admin"

    async def test_non_spiffe_subject_returns_none(self, verifier):
        token = _make_jwt_svid("user@example.com")
        result = await verifier.verify_token(token)
        assert result is None

    async def test_wrong_trust_domain_returns_none(self, verifier):
        token = _make_jwt_svid("spiffe://wrong.org/workload/web")
        result = await verifier.verify_token(token)
        assert result is None

    async def test_invalid_token_returns_none(self, verifier):
        result = await verifier.verify_token("not-a-jwt")
        assert result is None

    async def test_audience_match_string(self, verifier_with_audience):
        token = _make_jwt_svid("spiffe://example.org/workload/web", aud="linux-mcp")
        result = await verifier_with_audience.verify_token(token)
        assert result is not None

    async def test_audience_match_list(self, verifier_with_audience):
        token = _make_jwt_svid("spiffe://example.org/workload/web", aud=["linux-mcp", "other"])
        result = await verifier_with_audience.verify_token(token)
        assert result is not None

    async def test_audience_mismatch_returns_none(self, verifier_with_audience):
        token = _make_jwt_svid("spiffe://example.org/workload/web", aud="wrong-audience")
        result = await verifier_with_audience.verify_token(token)
        assert result is None

    async def test_audience_mismatch_list_returns_none(self, verifier_with_audience):
        token = _make_jwt_svid("spiffe://example.org/workload/web", aud=["wrong", "also-wrong"])
        result = await verifier_with_audience.verify_token(token)
        assert result is None

    async def test_scopes_extracted(self, verifier):
        token = _make_jwt_svid("spiffe://example.org/workload/web", scope="read write")
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.scopes == ["read", "write"]

    async def test_no_scopes_returns_empty(self, verifier):
        token = _make_jwt_svid("spiffe://example.org/workload/web")
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.scopes == []
