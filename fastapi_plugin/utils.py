from typing import Optional
from urllib.parse import urlparse, urlunparse

from fastapi import HTTPException, Request


def http_exception(
    status_code: int,
    error: str,
    error_desc: str,
    headers: Optional[dict[str, str]] = None
) -> HTTPException:
    """
    Build an OAuth2-compliant :class:`fastapi.HTTPException`.

    The response body always uses the shape ``{"error": ..., "error_description": ...}``
    so API consumers receive a consistent error format regardless of status code.

    When called after catching a :class:`BaseAuthError`, pass the headers returned
    by ``BaseAuthError.get_headers()`` so that the correct ``WWW-Authenticate``
    challenge is forwarded to the client.

    :param status_code: The HTTP status code to return, for example ``401`` or ``403``.
    :type status_code: int

    :param error: A short OAuth2 error code such as ``"invalid_token"`` or
        ``"insufficient_scope"``.
    :type error: str

    :param error_desc: A human-readable description of the error.
    :type error_desc: str

    :param headers: Optional response headers. Pass ``BaseAuthError.get_headers()``
        here to include ``WWW-Authenticate`` challenges on 401 responses.
    :type headers: dict[str, str], optional

    :returns: An :class:`fastapi.HTTPException` ready to be raised.
    :rtype: HTTPException
    """
    return HTTPException(
        status_code=status_code,
        detail={
            "error": error,
            "error_description": error_desc
        },
        headers=headers or {}
    )

def _should_trust_proxy(request: Request) -> bool:
    """
    Return whether ``X-Forwarded-*`` headers should be trusted for this request.

    Trust is disabled by default. Enable it by setting ``app.state.trust_proxy = True``
    on your FastAPI application. Only do this when your app sits behind a known
    reverse proxy; enabling it on a publicly exposed server allows clients to
    spoof forwarded headers.

    :param request: The incoming FastAPI request.
    :type request: Request

    :returns: ``True`` if proxy headers should be trusted, ``False`` otherwise.
    :rtype: bool
    """

def _parse_forwarded_host(forwarded_host: Optional[str]) -> Optional[str]:
    """
    Extract the original client-facing host from an ``X-Forwarded-Host`` header.

    When a request passes through multiple proxies, each proxy may append its
    own value separated by a comma. This function returns only the first (outermost)
    value, which represents the host the client originally used.

    :param forwarded_host: The raw value of the ``X-Forwarded-Host`` header.
    :type forwarded_host: str, optional

    :returns: The first host value with surrounding whitespace stripped, or
        ``None`` if the input is empty or blank.
    :rtype: str or None
    """
    if not forwarded_host:
        return None

    # Handle comma-separated values (multiple proxies)
    comma_index = forwarded_host.find(',')
    if comma_index != -1:
        forwarded_host = forwarded_host[:comma_index].rstrip()

    return forwarded_host.strip() or None

def get_canonical_url(request: Request) -> str:
    """
    Build the canonical URL that the client used to make this request.

    For DPoP validation, the ``htu`` claim in the DPoP proof must match the
    URL the client targeted. When the app runs behind a reverse proxy, the
    internal URL seen by FastAPI differs from the public URL the client used.
    This function reconstructs the correct public URL by reading
    ``X-Forwarded-Proto``, ``X-Forwarded-Host``, and ``X-Forwarded-Prefix``
    headers, but only when proxy trust is explicitly enabled via
    ``app.state.trust_proxy = True``.

    The URL fragment is always stripped because the DPoP spec excludes it
    from the ``htu`` claim.

    :param request: The incoming FastAPI request.
    :type request: Request

    :returns: The canonical URL string, for example
        ``"https://api.example.com/v1/items"``.
    :rtype: str

    **Enabling reverse proxy support**

    .. code-block:: python

        app = FastAPI()
        app.state.trust_proxy = True
    """
    # Start with the direct connection URL
    parsed = urlparse(str(request.url))

    # Default to direct request values
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path

    # Only process X-Forwarded headers if proxy is trusted
    if _should_trust_proxy(request):
        # X-Forwarded-Proto: Override scheme if present
        forwarded_proto = request.headers.get("x-forwarded-proto")
        if forwarded_proto:
            proto = forwarded_proto.strip().lower()
            if proto in ("http", "https"):
                scheme = proto

        # X-Forwarded-Host: Override host, handling multiple proxies
        forwarded_host = request.headers.get("x-forwarded-host")
        parsed_host = _parse_forwarded_host(forwarded_host)
        if parsed_host:
            netloc = parsed_host

        # X-Forwarded-Prefix: Prepend path prefix
        forwarded_prefix = request.headers.get("x-forwarded-prefix", "").strip()
        if forwarded_prefix and not any([
            ".." in forwarded_prefix, forwarded_prefix.startswith("//"),
            ":" in forwarded_prefix, "\x00" in forwarded_prefix,
            "%2e%2e" in forwarded_prefix.lower()
        ]):
            if not forwarded_prefix.startswith("/"):
                forwarded_prefix = "/" + forwarded_prefix
            path = forwarded_prefix.rstrip("/") + path

    canonical_url = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # No fragment in DPoP htu claim
    ))

    return canonical_url

def validate_scopes(claims: dict, required_scopes: list[str]) -> bool:
    """
    Check that a token's ``scope`` claim includes every required scope.

    The ``scope`` claim is expected to be a space-delimited string as defined
    by RFC 6749. All values in ``required_scopes`` must be present for this
    function to return ``True``. A missing or empty ``scope`` claim always
    returns ``False``.

    :param claims: The decoded JWT claims dictionary.
    :type claims: dict

    :param required_scopes: The list of scope strings that must all be present.
    :type required_scopes: list[str]

    :returns: ``True`` if every required scope is in the token, ``False`` otherwise.
    :rtype: bool

    .. code-block:: python

        claims = {"scope": "read:items write:items"}

        validate_scopes(claims, ["read:items"])              # True
        validate_scopes(claims, ["read:items", "delete:items"])  # False
    """
    scope_str = claims.get("scope")
    if not scope_str:
        return False

    token_scopes = scope_str.split()  # space-delimited
    return all(req in token_scopes for req in required_scopes)
