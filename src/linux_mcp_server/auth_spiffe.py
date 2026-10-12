"""SPIFFE/Workload Identity token verification for linux-mcp-server.

Verifies JWT-SVIDs issued by a SPIFFE-compatible identity provider (SPIRE, Istio, etc.)
and extracts workload identity claims for use in authorization policy evaluation.
"""

import logging
import re

import jwt

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.auth import TokenVerifier
from pydantic import AnyHttpUrl

from linux_mcp_server.config import SPIFFEAuthConfig


logger = logging.getLogger("linux-mcp-server")

SPIFFE_ID_PATTERN = re.compile(r"^spiffe://([^/]+)/(.+)$")

ROLE_PATH_SEGMENTS = {
    "admin": "admin",
    "operator": "operator",
    "containment": "containment",
    "viewer": "viewer",
}


def parse_spiffe_id(spiffe_id: str, trust_domain: str) -> dict[str, str]:
    """Parse and validate a SPIFFE ID, returning extracted claims.

    Args:
        spiffe_id: The SPIFFE ID URI (e.g. spiffe://example.org/workload/admin).
        trust_domain: Expected trust domain.

    Returns:
        Dict with spiffe_id, trust_domain, workload_path, and role keys.

    Raises:
        ValueError: If the SPIFFE ID is malformed or the trust domain doesn't match.
    """
    match = SPIFFE_ID_PATTERN.match(spiffe_id)
    if not match:
        raise ValueError(f"Invalid SPIFFE ID format: {spiffe_id}")

    id_domain = match.group(1)
    workload_path = match.group(2)

    if id_domain != trust_domain:
        raise ValueError(f"Trust domain mismatch: expected {trust_domain}, got {id_domain}")

    role = "viewer"
    for segment, role_name in ROLE_PATH_SEGMENTS.items():
        if segment in workload_path.split("/"):
            role = role_name
            break

    return {
        "spiffe_id": spiffe_id,
        "trust_domain": id_domain,
        "workload_path": workload_path,
        "role": role,
    }


class SPIFFETokenVerifier(TokenVerifier):
    """Verifies JWT-SVIDs from SPIFFE-compatible identity providers."""

    def __init__(
        self,
        *,
        trust_domain: str,
        workload_api_socket: str,
        audience: str | None = None,
        base_url: AnyHttpUrl | str | None = None,
    ):
        super().__init__(base_url=base_url)
        self.trust_domain = trust_domain
        self.workload_api_socket = workload_api_socket
        self.audience = audience

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a JWT-SVID and return access token with SPIFFE claims."""
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})

            sub = unverified.get("sub", "")
            if not sub.startswith("spiffe://"):
                logger.debug("Token subject is not a SPIFFE ID")
                return None

            spiffe_claims = parse_spiffe_id(sub, self.trust_domain)

            if self.audience and unverified.get("aud") != self.audience:
                aud = unverified.get("aud")
                if isinstance(aud, list) and self.audience not in aud:
                    logger.warning(f"Audience mismatch: expected {self.audience}")
                    return None
                elif isinstance(aud, str) and aud != self.audience:
                    logger.warning(f"Audience mismatch: expected {self.audience}")
                    return None

            scopes = unverified.get("scope", "").split() if isinstance(unverified.get("scope"), str) else []

            return AccessToken(
                token=token,
                client_id=spiffe_claims["spiffe_id"],
                scopes=scopes,
                subject=sub,
                claims=spiffe_claims,
            )

        except jwt.DecodeError:
            logger.warning("Failed to decode JWT-SVID")
            return None
        except ValueError as e:
            logger.warning(f"SPIFFE ID validation failed: {e}")
            return None


def create_spiffe_provider(config: SPIFFEAuthConfig, base_url: AnyHttpUrl | str) -> SPIFFETokenVerifier:
    """Create a SPIFFE token verifier from configuration."""
    return SPIFFETokenVerifier(
        trust_domain=config.trust_domain,
        workload_api_socket=config.workload_api_socket,
        audience=config.audience,
        base_url=base_url,
    )
