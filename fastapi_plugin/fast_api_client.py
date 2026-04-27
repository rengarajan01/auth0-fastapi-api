from typing import Callable, Optional, Union

from auth0_api_python.api_client import ApiClient, ApiClientOptions, BaseAuthError
from auth0_api_python.cache import CacheAdapter
from fastapi import Request

from .utils import get_canonical_url, http_exception, validate_scopes


class Auth0FastAPI:
    """
    The main class for protecting FastAPI routes with Auth0.

    Create one instance per application and use :meth:`require_auth` to
    guard individual routes. The instance exposes ``api_client`` for advanced
    use cases such as token exchange.

    **Single domain setup**

    .. code-block:: python

        from auth0_fastapi_api import Auth0FastAPI

        auth0 = Auth0FastAPI(
            domain="your-tenant.us.auth0.com",
            audience="https://api.example.com"
        )

    **Multiple custom domains setup**

    .. code-block:: python

        auth0 = Auth0FastAPI(
            domains=["tenant-a.us.auth0.com", "tenant-b.us.auth0.com"],
            audience="https://api.example.com"
        )
    """

    def __init__(
        self,
        domain: Optional[str] = None,
        audience: str = "",
        domains: Optional[Union[list[str], Callable]] = None,
        client_id=None,
        client_secret=None,
        custom_fetch=None,
        dpop_enabled=True,
        dpop_required=False,
        dpop_iat_leeway=30,
        dpop_iat_offset=300,
        cache_adapter: Optional[CacheAdapter] = None,
        cache_ttl_seconds: int = 600,
        cache_max_entries: int = 100):
        """
        Configure the Auth0FastAPI instance.

        You must provide either ``domain`` or ``domains``, and ``audience`` is always required.

        :param domain: Your Auth0 tenant domain, for example ``"your-tenant.us.auth0.com"``.
            Use this for single-tenant setups. Omit when using ``domains``.
        :type domain: str, optional

        :param audience: The API identifier registered in the Auth0 Dashboard.
            This must match the ``aud`` claim in incoming tokens. Required.
        :type audience: str

        :param domains: A list of allowed Auth0 domains, or a callable that resolves
            domains at request time. Use this for multi-tenant setups where tokens
            may come from different Auth0 tenants.

            When passing a callable, it receives a :class:`DomainsResolverContext`
            and must return a list of allowed domain strings.

            .. code-block:: python

                def resolve(ctx: DomainsResolverContext) -> list[str]:
                    # ctx.unverified_iss contains the issuer from the token
                    return ["tenant-a.us.auth0.com"]

                auth0 = Auth0FastAPI(domains=resolve, audience="https://api.example.com")

        :type domains: list[str] or Callable, optional

        :param client_id: The client ID used for token exchange flows.
        :type client_id: str, optional

        :param client_secret: The client secret used for token exchange flows.
        :type client_secret: str, optional

        :param custom_fetch: A custom async HTTP function to replace the default
            HTTP client used by the underlying SDK. Useful for testing or proxying.
        :type custom_fetch: Callable, optional

        :param dpop_enabled: Accept DPoP-bound tokens in addition to Bearer tokens.
            Defaults to ``True``.
        :type dpop_enabled: bool

        :param dpop_required: When ``True``, only DPoP tokens are accepted. Requests
            using a plain Bearer token are rejected with a 401. Defaults to ``False``.
        :type dpop_required: bool

        :param dpop_iat_leeway: Clock skew tolerance in seconds when validating the
            ``iat`` claim of a DPoP proof. Defaults to ``30``.
        :type dpop_iat_leeway: int

        :param dpop_iat_offset: Maximum acceptable age of a DPoP proof in seconds.
            Proofs older than this value are rejected. Defaults to ``300``.
        :type dpop_iat_offset: int

        :param cache_adapter: A custom cache backend that implements :class:`CacheAdapter`.
            When provided, ``cache_max_entries`` is ignored and you configure the
            cache directly on your adapter. Defaults to an in-memory LRU cache.
        :type cache_adapter: CacheAdapter, optional

        :param cache_ttl_seconds: How long JWKS results are cached in seconds.
            Defaults to ``600``.
        :type cache_ttl_seconds: int

        :param cache_max_entries: Maximum number of entries in the default in-memory
            cache before the least-recently-used entry is evicted. Ignored when
            ``cache_adapter`` is provided. Defaults to ``100``.
        :type cache_max_entries: int

        :raises ValueError: If ``audience`` is not provided.
        """
        if not audience:
            raise ValueError("audience is required.")

        self.api_client = ApiClient(
            ApiClientOptions(
                domain=domain,
                audience=audience,
                domains=domains,
                client_id=client_id,
                client_secret=client_secret,
                custom_fetch=custom_fetch,
                dpop_enabled=dpop_enabled,
                dpop_required=dpop_required,
                dpop_iat_leeway=dpop_iat_leeway,
                dpop_iat_offset=dpop_iat_offset,
                cache_adapter=cache_adapter,
                cache_ttl_seconds=cache_ttl_seconds,
                cache_max_entries=cache_max_entries
            )
        )

    def require_auth(
        self,
        scopes: Optional[Union[str, list[str]]] = None
    ):
        """
        Return a FastAPI dependency that validates the incoming request's access token.

        Attach this to any route using FastAPI's ``Depends()``. The dependency
        automatically detects whether the client is using a Bearer token or a
        DPoP-bound token, validates it against Auth0, and returns the decoded
        JWT claims on success.

        If ``scopes`` are specified, the token's ``scope`` claim must contain
        every scope in the list. A missing or insufficient scope returns a 403.

        :param scopes: One or more OAuth2 scopes that the token must include.
            Pass a single string or a list of strings.
        :type scopes: str or list[str], optional

        :returns: An async dependency callable that resolves to a ``dict`` containing
            the decoded JWT claims (for example ``sub``, ``scope``, ``iss``, ``aud``).
        :rtype: Callable

        :raises HTTPException 401: When the token is missing, expired, or invalid.
        :raises HTTPException 403: When the token does not contain the required scopes.
        :raises HTTPException 500: When an unexpected error occurs during validation.

        **Basic usage**

        .. code-block:: python

            from fastapi import Depends, FastAPI
            from auth0_fastapi_api import Auth0FastAPI

            app = FastAPI()
            auth0 = Auth0FastAPI(
                domain="your-tenant.us.auth0.com",
                audience="https://api.example.com"
            )

            @app.get("/profile")
            async def get_profile(claims: dict = Depends(auth0.require_auth())):
                return {"user_id": claims["sub"]}

        **Requiring specific scopes**

        .. code-block:: python

            @app.get("/items")
            async def list_items(claims: dict = Depends(auth0.require_auth(scopes=["read:items"]))):
                return {"items": []}

            @app.post("/items")
            async def create_item(claims: dict = Depends(auth0.require_auth(scopes=["write:items"]))):
                return {"created": True}
        """
        async def _dependency(request: Request) -> dict:
            try:
                claims = await self.api_client.verify_request(
                    headers=dict(request.headers),
                    http_method=request.method,
                    http_url=get_canonical_url(request)
                )
            except BaseAuthError as e:
                raise http_exception(
                    status_code=e.get_status_code(),
                    error=e.get_error_code(),
                    error_desc=e.get_error_description(),
                    headers=e.get_headers()
                )
            except Exception:
                # Handle any unexpected errors
                raise http_exception(
                    status_code=500,
                    error="internal_server_error",
                    error_desc="An unexpected error occurred during authentication"
                )

            # If scopes needed, validate
            if scopes:
                required_scopes = [scopes] if isinstance(scopes, str) else scopes
                if not validate_scopes(claims, required_scopes):
                    raise http_exception(
                        status_code=403,
                        error="insufficient_scope",
                        error_desc="Insufficient scopes"
                    )

            # Return the claims as the "user" info
            return claims

        return _dependency
