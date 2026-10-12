import logging

from fastmcp.server.auth.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

from linux_mcp_server.auth_spiffe import create_spiffe_provider
from linux_mcp_server.config import AuthConfig
from linux_mcp_server.config import AuthProvider
from linux_mcp_server.config import CONFIG


logger = logging.getLogger("linux-mcp-server")


def _create_google_provider(auth: AuthConfig, base_url: str):
    if auth.google is None:
        raise ValueError("Google auth provider selected but LINUX_MCP_AUTH__GOOGLE__* not configured")

    return GoogleProvider(
        client_id=auth.google.client_id,
        client_secret=auth.google.client_secret.get_secret_value(),
        base_url=base_url,
    )


def _create_github_provider(auth: AuthConfig, base_url: str):
    if auth.github is None:
        raise ValueError("GitHub auth provider selected but LINUX_MCP_AUTH__GITHUB__* not configured")

    return GitHubProvider(
        client_id=auth.github.client_id,
        client_secret=auth.github.client_secret.get_secret_value(),
        base_url=base_url,
    )


def _create_jwt_provider(auth: AuthConfig, base_url: str):
    if auth.jwt is None:
        raise ValueError("JWT auth provider selected but LINUX_MCP_AUTH__JWT__* not configured")

    verifier = JWTVerifier(
        jwks_uri=auth.jwt.jwks_uri,
        issuer=auth.jwt.issuer,
        audience=auth.jwt.audience,
    )

    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(auth.jwt.issuer)],
        base_url=base_url,
    )


def _create_introspection_provider(auth: AuthConfig, base_url: str):
    if auth.introspection is None:
        raise ValueError("LINUX_MCP_AUTH__INTROSPECTION__* not configured")

    verifier = IntrospectionTokenVerifier(
        introspection_url=auth.introspection.introspection_url,
        client_id=auth.introspection.client_id,
        client_secret=auth.introspection.client_secret.get_secret_value(),
        timeout_seconds=auth.introspection.timeout_seconds,
    )

    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(auth.introspection.issuer)],
        base_url=base_url,
    )


def _create_spiffe_provider_from_config(auth: AuthConfig, base_url: str):
    if auth.spiffe is None:
        raise ValueError("SPIFFE auth provider selected but LINUX_MCP_AUTH__SPIFFE__* not configured")

    return create_spiffe_provider(auth.spiffe, base_url)


_PROVIDER_FACTORIES = {
    AuthProvider.GOOGLE: _create_google_provider,
    AuthProvider.GITHUB: _create_github_provider,
    AuthProvider.JWT: _create_jwt_provider,
    AuthProvider.INTROSPECTION: _create_introspection_provider,
    AuthProvider.SPIFFE: _create_spiffe_provider_from_config,
}


# Create authentication provider based on configuration
def create_auth_provider():

    if CONFIG.auth is None:
        return None

    if CONFIG.auth.provider is None:
        return None

    factory = _PROVIDER_FACTORIES.get(CONFIG.auth.provider)
    if factory is None:
        raise ValueError(f"Unknown auth provider: {CONFIG.auth.provider}")

    return factory(CONFIG.auth, CONFIG.effective_base_url)
