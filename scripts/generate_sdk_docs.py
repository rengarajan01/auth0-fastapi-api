#!/usr/bin/env python3
"""
Reads fastapi_plugin source, extracts the public API surface from docstrings
and signatures, and outputs sdk-data/auth0-fastapi-api/v1.json conforming to
the Auth0 SDK documentation JSON schema consumed by generate-sdk-docs.mjs.

Run:
    python scripts/generate_sdk_docs.py
"""

import inspect
import json
import re
import sys
import typing
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi_plugin import (
    Auth0FastAPI,
    CacheAdapter,
    ConfigurationError,
    DomainsResolver,
    DomainsResolverContext,
    DomainsResolverError,
    InMemoryCache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_version() -> str:
    content = (REPO_ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    return match.group(1) if match else "unknown"


def strip_rst_roles(text: str) -> str:
    """Convert :role:`target` to just `target`."""
    return re.sub(r":[a-z]+:`([^`]+)`", r"`\1`", text)


def strip_rst_directives(text: str) -> str:
    """Remove .. directive:: blocks entirely."""
    return re.sub(r"\.\. \w[^:]*::.*?(?=\n\S|\Z)", "", text, flags=re.DOTALL)


def first_paragraph(text: str) -> str:
    """Return only the first paragraph of a block of text."""
    return text.split("\n\n")[0].strip()


def clean_text(text: str) -> str:
    """Strip RST markup and normalize whitespace for use in JSON descriptions."""
    text = strip_rst_directives(text)
    text = strip_rst_roles(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_code_blocks(docstring: str) -> list[dict]:
    """Pull every ``.. code-block:: python`` section out of a docstring."""
    examples = []
    pattern = re.compile(
        r"\.\. code-block::\s*python\s*\n((?:[ \t]+[^\n]*\n?|\n)+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(docstring):
        raw = match.group(1)
        lines = raw.split("\n")
        non_empty = [l for l in lines if l.strip()]
        if not non_empty:
            continue
        indent = min(len(l) - len(l.lstrip()) for l in non_empty)
        code = "\n".join(l[indent:] if l.strip() else "" for l in lines).strip()
        if code:
            examples.append({"title": "", "language": "python", "code": code})
    return examples


# ---------------------------------------------------------------------------
# Sphinx docstring parser
# ---------------------------------------------------------------------------

def parse_docstring(docstring: str) -> dict:
    """
    Parse a Sphinx-style docstring into structured components.

    Returns a dict with keys:
        description, params, returns, raises, examples
    """
    empty = {"description": "", "params": [], "returns": None, "raises": [], "examples": []}
    if not docstring:
        return empty

    examples = extract_code_blocks(docstring)

    # Split at the first Sphinx field marker
    field_start = re.search(r"^:(?:param|type|returns?|rtype|raises?)", docstring, re.MULTILINE)
    if field_start:
        desc_raw = docstring[: field_start.start()]
        fields_raw = docstring[field_start.start() :]
    else:
        desc_raw = docstring
        fields_raw = ""

    description = clean_text(desc_raw)

    # Join continuation lines (lines starting with whitespace) onto the previous
    normalized = re.sub(r"\n[ \t]+", " ", fields_raw)

    params: dict[str, dict] = {}
    param_types: dict[str, str] = {}
    returns_desc = ""
    returns_type = ""
    raises = []

    for line in normalized.splitlines():
        line = line.strip()
        if not line:
            continue

        m = re.match(r"^:param\s+(\w+):\s*(.*)", line)
        if m:
            # Take only the first sentence of the description to keep it concise
            desc = strip_rst_roles(m.group(2).strip())
            desc = strip_rst_directives(desc).strip()
            params[m.group(1)] = {"description": first_paragraph(desc)}
            continue

        m = re.match(r"^:type\s+(\w+):\s*(.*)", line)
        if m:
            param_types[m.group(1)] = m.group(2).strip()
            continue

        m = re.match(r"^:returns?:\s*(.*)", line)
        if m:
            returns_desc = strip_rst_roles(m.group(1).strip())
            continue

        m = re.match(r"^:rtype:\s*(.*)", line)
        if m:
            returns_type = m.group(1).strip()
            continue

        # :raises SomeError: description  (status codes after the name are stripped)
        m = re.match(r"^:raises?\s+([\w\s]+?):\s*(.*)", line)
        if m:
            exc_name = m.group(1).strip().split()[0]
            raises.append({
                "name": exc_name,
                "type": exc_name,
                "description": strip_rst_roles(m.group(2).strip()),
            })
            continue

    params_list = []
    for name, data in params.items():
        raw_type = param_types.get(name, "")
        optional = (
            "optional" in raw_type.lower()
            or name in ("domain", "domains", "client_id", "client_secret",
                        "custom_fetch", "cache_adapter")
        )
        entry: dict = {
            "name": name,
            "type": raw_type,
            "optional": optional,
            "description": data["description"],
        }
        params_list.append(entry)

    returns = None
    if returns_desc or returns_type:
        returns = {"type": returns_type, "description": returns_desc}

    return {
        "description": description,
        "params": params_list,
        "returns": returns,
        "raises": raises,
        "examples": examples,
    }


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------

def class_signature(cls) -> str:
    try:
        sig = inspect.signature(cls.__init__)
        params = [p for name, p in sig.parameters.items() if name != "self"]
        return f"{cls.__name__}({', '.join(str(p) for p in params)})"
    except (TypeError, ValueError):
        return f"{cls.__name__}()"


def method_signature(cls, method_name: str) -> str:
    method = getattr(cls, method_name, None)
    if not method:
        return f"{method_name}()"
    try:
        sig = inspect.signature(method)
        params = [p for name, p in sig.parameters.items() if name != "self"]
        return f"{method_name}({', '.join(str(p) for p in params)})"
    except (TypeError, ValueError):
        return f"{method_name}()"


# ---------------------------------------------------------------------------
# Page builders
# ---------------------------------------------------------------------------

def build_auth0_fastapi_page() -> dict:
    class_doc = parse_docstring(inspect.getdoc(Auth0FastAPI))
    init_doc = parse_docstring(inspect.getdoc(Auth0FastAPI.__init__))
    method_doc = parse_docstring(inspect.getdoc(Auth0FastAPI.require_auth))

    return {
        "id": "auth0-fastapi",
        "title": "Auth0FastAPI",
        "kind": "class",
        "description": class_doc["description"],
        "constructor": {
            "signature": class_signature(Auth0FastAPI),
            "parameters": init_doc["params"],
        },
        "members": [
            {
                "id": "require-auth",
                "title": "require_auth",
                "kind": "method",
                "signature": method_signature(Auth0FastAPI, "require_auth"),
                "description": method_doc["description"],
                "parameters": method_doc["params"],
                "returns": method_doc["returns"],
                "throws": method_doc["raises"],
                "examples": method_doc["examples"],
            }
        ],
        "examples": class_doc["examples"],
    }


def build_cache_adapter_page() -> dict:
    doc = parse_docstring(inspect.getdoc(CacheAdapter))

    # Collect public abstract methods as members
    members = []
    for name, obj in inspect.getmembers(CacheAdapter, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        m_doc = parse_docstring(inspect.getdoc(obj))
        try:
            sig = inspect.signature(obj)
            params = [p for n, p in sig.parameters.items() if n != "self"]
            signature = f"{name}({', '.join(str(p) for p in params)})"
        except (TypeError, ValueError):
            signature = f"{name}()"

        member: dict = {
            "id": name.replace("_", "-"),
            "title": name,
            "kind": "method",
            "signature": signature,
            "description": m_doc["description"],
        }
        if m_doc["params"]:
            member["parameters"] = m_doc["params"]
        if m_doc["returns"]:
            member["returns"] = m_doc["returns"]
        members.append(member)

    page: dict = {
        "id": "cache-adapter",
        "title": "CacheAdapter",
        "kind": "interface",
        "description": doc["description"] or "Abstract base class for implementing a custom JWKS cache backend.",
    }
    if members:
        page["members"] = members
    return page


def build_in_memory_cache_page() -> dict:
    doc = parse_docstring(inspect.getdoc(InMemoryCache))
    init_doc = parse_docstring(inspect.getdoc(InMemoryCache.__init__))

    page: dict = {
        "id": "in-memory-cache",
        "title": "InMemoryCache",
        "kind": "class",
        "description": doc["description"] or "Default in-memory LRU cache for JWKS results. Used automatically unless a custom cache_adapter is provided.",
        "constructor": {
            "signature": class_signature(InMemoryCache),
            "parameters": init_doc["params"],
        },
    }
    if doc["examples"]:
        page["examples"] = doc["examples"]
    return page


def build_domains_resolver_page() -> dict:
    raw_doc = inspect.getdoc(DomainsResolver) or ""
    description = (
        clean_text(raw_doc)
        if raw_doc
        else "Type alias for a callable that resolves allowed Auth0 domains at request time. Used in multi-tenant setups."
    )

    return {
        "id": "domains-resolver",
        "title": "DomainsResolver",
        "kind": "type",
        "description": description,
        "type": "Callable[[DomainsResolverContext], list[str]]",
        "examples": [
            {
                "title": "",
                "language": "python",
                "code": (
                    "from auth0_fastapi_api import Auth0FastAPI, DomainsResolverContext\n\n"
                    "def resolve_domains(ctx: DomainsResolverContext) -> list[str]:\n"
                    "    if ctx.unverified_iss.endswith('.us.auth0.com'):\n"
                    "        return ['tenant-a.us.auth0.com']\n"
                    "    return ['tenant-b.eu.auth0.com']\n\n"
                    "auth0 = Auth0FastAPI(\n"
                    "    domains=resolve_domains,\n"
                    "    audience='https://api.example.com'\n"
                    ")"
                ),
            }
        ],
    }


def build_domains_resolver_context_page() -> dict:
    doc = parse_docstring(inspect.getdoc(DomainsResolverContext))

    # Try to read annotated fields from the class; fall back to known fields
    properties = []
    try:
        hints = typing.get_type_hints(DomainsResolverContext)
        known_descriptions = {
            "unverified_iss": "The issuer claim extracted from the token before signature verification. Use this to decide which tenant to allow.",
            "request_url": "The URL of the incoming request.",
            "request_headers": "The headers of the incoming request as a dictionary.",
        }
        for field_name, field_type in hints.items():
            if field_name.startswith("_"):
                continue
            type_str = (
                field_type.__name__
                if hasattr(field_type, "__name__")
                else str(field_type)
            )
            properties.append({
                "name": field_name,
                "type": type_str,
                "description": known_descriptions.get(field_name, ""),
            })
    except Exception:
        properties = [
            {
                "name": "unverified_iss",
                "type": "str",
                "description": "The issuer claim extracted from the token before signature verification. Use this to decide which tenant to allow.",
            },
            {
                "name": "request_url",
                "type": "str",
                "description": "The URL of the incoming request.",
            },
            {
                "name": "request_headers",
                "type": "dict[str, str]",
                "description": "The headers of the incoming request as a dictionary.",
            },
        ]

    return {
        "id": "domains-resolver-context",
        "title": "DomainsResolverContext",
        "kind": "interface",
        "description": doc["description"] or "Context object passed to a DomainsResolver callable. Contains request details to help route to the correct Auth0 tenant.",
        "properties": properties,
    }


def build_domains_resolver_error_page() -> dict:
    doc = parse_docstring(inspect.getdoc(DomainsResolverError))
    return {
        "id": "domains-resolver-error",
        "title": "DomainsResolverError",
        "kind": "class",
        "description": doc["description"] or "Raised when a DomainsResolver callable returns an unexpected result or throws during resolution.",
    }


def build_configuration_error_page() -> dict:
    doc = parse_docstring(inspect.getdoc(ConfigurationError))
    return {
        "id": "configuration-error",
        "title": "ConfigurationError",
        "kind": "class",
        "description": doc["description"] or "Raised when the SDK is misconfigured, for example when a required parameter like audience is missing.",
        "examples": [
            {
                "title": "",
                "language": "python",
                "code": (
                    "from auth0_fastapi_api import Auth0FastAPI\n\n"
                    "# audience is required — omitting it raises ConfigurationError\n"
                    "auth0 = Auth0FastAPI(domain='YOUR_AUTH0_DOMAIN')"
                ),
            }
        ],
    }


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------

NAVIGATION = [
    {
        "section": "Core",
        "items": [
            {"id": "auth0-fastapi", "title": "Auth0FastAPI", "kind": "class"},
        ],
    },
    {
        "section": "Cache",
        "items": [
            {"id": "cache-adapter", "title": "CacheAdapter", "kind": "interface"},
            {"id": "in-memory-cache", "title": "InMemoryCache", "kind": "class"},
        ],
    },
    {
        "section": "Multi-Domain",
        "items": [
            {"id": "domains-resolver", "title": "DomainsResolver", "kind": "type"},
            {"id": "domains-resolver-context", "title": "DomainsResolverContext", "kind": "interface"},
            {"id": "domains-resolver-error", "title": "DomainsResolverError", "kind": "class"},
        ],
    },
    {
        "section": "Errors",
        "items": [
            {"id": "configuration-error", "title": "ConfigurationError", "kind": "class"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    out_path = REPO_ROOT / "sdk-data" / "auth0-fastapi-api" / "v1.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pages = {
        "auth0-fastapi": build_auth0_fastapi_page(),
        "cache-adapter": build_cache_adapter_page(),
        "in-memory-cache": build_in_memory_cache_page(),
        "domains-resolver": build_domains_resolver_page(),
        "domains-resolver-context": build_domains_resolver_context_page(),
        "domains-resolver-error": build_domains_resolver_error_page(),
        "configuration-error": build_configuration_error_page(),
    }

    payload = {
        "meta": {
            "package": "auth0-fastapi-api",
            "version": get_version(),
            "status": "active",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        },
        "navigation": NAVIGATION,
        "pages": pages,
    }

    out_path.write_text(json.dumps(payload, indent=2))
    print(f"Generated {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
