"""
auth0-fastapi-api
=================

Auth0 SDK for protecting FastAPI routes using JWT access token validation.

Supports Bearer tokens, DPoP-bound tokens, and multi-tenant setups with
multiple custom domains.

**Quick start**

.. code-block:: python

    from fastapi import Depends, FastAPI
    from auth0_fastapi_api import Auth0FastAPI

    app = FastAPI()

    auth0 = Auth0FastAPI(
        domain="your-tenant.us.auth0.com",
        audience="https://api.example.com"
    )

    @app.get("/protected")
    async def protected(claims: dict = Depends(auth0.require_auth())):
        return {"user_id": claims["sub"]}

**Exported symbols**

- :class:`Auth0FastAPI` - Main class for configuring and protecting routes.
- :class:`CacheAdapter` - Interface for providing a custom JWKS cache backend.
- :class:`InMemoryCache` - Default in-memory LRU cache used for JWKS results.
- :class:`ConfigurationError` - Raised when the SDK is misconfigured.
- :data:`DomainsResolver` - Type alias for the callable used in multi-domain setups.
- :class:`DomainsResolverContext` - Context object passed to a domains resolver callable.
- :class:`DomainsResolverError` - Raised when a domains resolver returns an unexpected result.
"""

from auth0_api_python import (
    CacheAdapter,
    ConfigurationError,
    DomainsResolver,
    DomainsResolverContext,
    DomainsResolverError,
    InMemoryCache,
)

from .fast_api_client import Auth0FastAPI

__all__ = [
    "Auth0FastAPI",
    "CacheAdapter",
    "ConfigurationError",
    "DomainsResolver",
    "DomainsResolverContext",
    "DomainsResolverError",
    "InMemoryCache",
]
