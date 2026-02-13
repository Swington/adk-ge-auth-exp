"""Bearer token credential propagation for SpannerToolset.

When Gemini Enterprise invokes the agent via A2A, it includes the end-user's
OAuth access token.  On Cloud Run (where the ``Authorization`` header is
consumed by Cloud Run's own IAM authentication), the user's access token is
expected in the ``X-User-Authorization`` header instead.

Header priority (first match wins):
    1. ``X-User-Authorization: Bearer <token>``   – used on Cloud Run
    2. ``Authorization: Bearer <token>``           – used locally / direct calls

This module:

1.  Provides ASGI middleware (AuthTokenExtractorMiddleware) that extracts the
    Bearer token and stores it in a contextvars.ContextVar so it is visible
    anywhere in the same async call-chain.

2.  Provides BearerTokenCredentialsManager — a drop-in replacement for
    GoogleCredentialsManager — that reads the token from the ContextVar and
    returns google.oauth2.credentials.Credentials(token=...).

3.  Provides BearerTokenSpannerToolset — a BaseToolset wrapper that creates an
    inner SpannerToolset and replaces _credentials_manager on every GoogleTool
    with the BearerTokenCredentialsManager.

4.  Monkey-patches ``google.cloud.spanner.Instance.database`` so that
    FGAC database roles are automatically applied based on the user's email
    (resolved from the OAuth token via Google tokeninfo).

Every step is logged so the pipeline can be traced end-to-end:
    [AUTH-MIDDLEWARE] → [AUTH-CREDS] → [AUTH-TOOLSET]
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any, Dict, List, Optional, Union

import google.auth
import google.cloud.spanner_v1.instance
import google.oauth2.credentials
import httpx
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset, ToolPredicate
from google.adk.tools.google_tool import GoogleTool
from google.adk.tools.spanner.settings import SpannerToolSettings
from google.adk.tools.spanner.spanner_toolset import SpannerToolset

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# User → Spanner database role mapping (for FGAC)
# ---------------------------------------------------------------------------
# Maps user email (or SA email) to the Spanner database role they should assume.
# Users not in this map connect without a database role (standard IAM access).
USER_DATABASE_ROLE_MAP: Dict[str, str] = {
    # Workspace user (Gemini Enterprise OAuth flow)
    "adk-auth-exp-3@switon.altostrat.com": "employees_reader",
    # Service account (integration tests / SA impersonation)
    "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com": "employees_reader",
}

# ---------------------------------------------------------------------------
# ContextVars: hold per-request state
# ---------------------------------------------------------------------------
_current_bearer_token: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("bearer_token", default=None)
)
_current_database_role: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("database_role", default=None)
)


def _resolve_user_email(token: str) -> Optional[str]:
    """Resolve the user's email from an OAuth access token.

    Tries two endpoints:
    1. tokeninfo (works when token has email scope)
    2. userinfo (works when token has email or openid scope)
    """
    # Try tokeninfo first
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"access_token": token},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            logger.info(
                "[AUTH-MIDDLEWARE] tokeninfo response keys=%s", list(data.keys())
            )
            email = data.get("email")
            if email:
                logger.info(
                    "[AUTH-MIDDLEWARE] Resolved token to email=%s via tokeninfo",
                    email,
                )
                return email
            logger.info(
                "[AUTH-MIDDLEWARE] tokeninfo has no email field, trying userinfo"
            )
        else:
            logger.warning(
                "[AUTH-MIDDLEWARE] tokeninfo returned status=%d", resp.status_code
            )
    except Exception as exc:
        logger.warning("[AUTH-MIDDLEWARE] tokeninfo call failed: %s", exc)

    # Fallback to userinfo endpoint
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            logger.info(
                "[AUTH-MIDDLEWARE] userinfo response keys=%s", list(data.keys())
            )
            email = data.get("email")
            if email:
                logger.info(
                    "[AUTH-MIDDLEWARE] Resolved token to email=%s via userinfo",
                    email,
                )
                return email
            logger.info("[AUTH-MIDDLEWARE] userinfo has no email field either")
        else:
            logger.warning(
                "[AUTH-MIDDLEWARE] userinfo returned status=%d", resp.status_code
            )
    except Exception as exc:
        logger.warning("[AUTH-MIDDLEWARE] userinfo call failed: %s", exc)

    logger.warning("[AUTH-MIDDLEWARE] Could not resolve email from token")
    return None


# ---------------------------------------------------------------------------
# Monkey-patch Instance.database() to inject database_role from ContextVar
# ---------------------------------------------------------------------------
_Instance = google.cloud.spanner_v1.instance.Instance
_original_instance_database = _Instance.database


def _patched_instance_database(self, database_id, *args, **kwargs):
    """Wrapper that injects database_role from the ContextVar if set."""
    db_role = _current_database_role.get()
    logger.info(
        "[AUTH-FGAC] Instance.database() called: database=%s, "
        "contextvar_role=%r, existing_role=%r",
        database_id,
        db_role,
        kwargs.get("database_role"),
    )
    if db_role and "database_role" not in kwargs:
        logger.info(
            "[AUTH-FGAC] Injecting database_role=%r for database=%s",
            db_role,
            database_id,
        )
        kwargs["database_role"] = db_role
    return _original_instance_database(self, database_id, *args, **kwargs)


_Instance.database = _patched_instance_database
logger.info("[AUTH-FGAC] Monkey-patched Instance.database() for FGAC support")


def get_bearer_token() -> Optional[str]:
    """Return the Bearer token for the current async context, or None."""
    return _current_bearer_token.get()


def set_bearer_token(token: Optional[str]) -> contextvars.Token:
    """Set the Bearer token for the current async context."""
    return _current_bearer_token.set(token)


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------
class AuthTokenExtractorMiddleware:
    """ASGI middleware that pulls the end-user's Bearer token from headers.

    Checks ``X-User-Authorization`` first (for Cloud Run deployments where
    ``Authorization`` is consumed by Cloud Run IAM), then falls back to
    ``Authorization``.

    Stores the token in ``_current_bearer_token`` so downstream code (running
    in the same async context) can access it via ``get_bearer_token()``.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    @staticmethod
    def _extract_bearer(headers: dict[bytes, bytes]) -> tuple[str | None, str]:
        """Extract Bearer token from headers.

        Returns (token, source_header) or (None, '').
        Priority: X-User-Authorization > Authorization.
        """
        # Check X-User-Authorization first (Cloud Run deployment)
        user_auth = headers.get(b"x-user-authorization", b"").decode()
        if user_auth.lower().startswith("bearer "):
            return user_auth[7:], "X-User-Authorization"

        # Fall back to Authorization (local / unauthenticated deployment)
        auth = headers.get(b"authorization", b"").decode()
        if auth.lower().startswith("bearer "):
            return auth[7:], "Authorization"

        return None, ""

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # ASGI headers are [(name_bytes, value_bytes), …]
        headers = dict(scope.get("headers", []))

        # Log all header names for debugging Gemini Enterprise requests
        header_names = [k.decode() for k in headers.keys()]
        logger.info(
            "[AUTH-MIDDLEWARE] Request %s %s — headers: %s",
            scope.get("method", "?"),
            scope.get("path", "?"),
            header_names,
        )

        token, source = self._extract_bearer(headers)

        if token:
            logger.info(
                "[AUTH-MIDDLEWARE] Extracted Bearer token from %s "
                "header (length=%d, first_20_chars=%s…)",
                source,
                len(token),
                token[:20],
            )
            reset_token = set_bearer_token(token)

            # Resolve user email and set database_role for FGAC
            db_role = None
            email = _resolve_user_email(token)
            if email:
                db_role = USER_DATABASE_ROLE_MAP.get(email)
                if db_role:
                    logger.info(
                        "[AUTH-MIDDLEWARE] User %s → database_role=%s",
                        email,
                        db_role,
                    )
            reset_role = _current_database_role.set(db_role)

            try:
                await self.app(scope, receive, send)
            finally:
                _current_bearer_token.reset(reset_token)
                _current_database_role.reset(reset_role)
        else:
            auth_value = headers.get(b"authorization", b"").decode()
            if auth_value:
                logger.info(
                    "[AUTH-MIDDLEWARE] Authorization header present but not "
                    "Bearer (starts with %r)",
                    auth_value[:30],
                )
            else:
                logger.info(
                    "[AUTH-MIDDLEWARE] No Authorization header in request"
                )
            await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Credentials manager (duck-types GoogleCredentialsManager)
# ---------------------------------------------------------------------------
class BearerTokenCredentialsManager:
    """Reads the Bearer token from the ContextVar and returns Credentials.

    If no token is present, returns None — which causes GoogleTool.run_async
    to return an "authorization required" message to the LLM.
    """

    async def get_valid_credentials(
        self, tool_context: Any
    ) -> Optional[google.oauth2.credentials.Credentials]:
        user_id = getattr(tool_context, "user_id", None)
        logger.info(
            "[AUTH-CREDS] get_valid_credentials called (user_id=%r)", user_id
        )

        token = get_bearer_token()
        if not token:
            logger.warning(
                "[AUTH-CREDS] No Bearer token in ContextVar for user_id=%r. "
                "Ensure AuthTokenExtractorMiddleware is active.",
                user_id,
            )
            return None

        logger.info(
            "[AUTH-CREDS] Creating google.oauth2.credentials.Credentials from "
            "Bearer token for user_id=%r (token length=%d, "
            "first_20_chars=%s…)",
            user_id,
            len(token),
            token[:20],
        )

        creds = google.oauth2.credentials.Credentials(token=token)
        logger.info(
            "[AUTH-CREDS] Credentials created (type=%s, valid=%s, "
            "expired=%s)",
            type(creds).__name__,
            creds.valid,
            creds.expired,
        )
        return creds


# ---------------------------------------------------------------------------
# Toolset wrapper
# ---------------------------------------------------------------------------
class BearerTokenSpannerToolset(BaseToolset):
    """Wraps SpannerToolset so every GoogleTool uses the Bearer token.

    Works by replacing ``_credentials_manager`` on each GoogleTool returned
    by the inner SpannerToolset with a ``BearerTokenCredentialsManager``.
    """

    def __init__(
        self,
        *,
        tool_filter: Optional[Union[ToolPredicate, List[str]]] = None,
        spanner_tool_settings: Optional[SpannerToolSettings] = None,
    ) -> None:
        super().__init__(tool_filter=tool_filter)
        self._creds_manager = BearerTokenCredentialsManager()

        # SpannerCredentialsConfig requires *either* credentials or
        # client_id+client_secret.  We pass ADC to satisfy validation;
        # the credentials will never actually be used because we replace
        # _credentials_manager on every tool.
        from google.adk.tools.spanner.spanner_credentials import (
            SpannerCredentialsConfig,
        )

        adc_creds, _ = google.auth.default()
        logger.info(
            "[AUTH-TOOLSET] Initialising inner SpannerToolset with ADC "
            "placeholder (type=%s)",
            type(adc_creds).__name__,
        )
        self._inner_toolset = SpannerToolset(
            credentials_config=SpannerCredentialsConfig(credentials=adc_creds),
            spanner_tool_settings=spanner_tool_settings,
            tool_filter=tool_filter,
        )

    async def get_tools(
        self, readonly_context: Optional[ReadonlyContext] = None
    ) -> List[BaseTool]:
        """Get tools from inner toolset with credentials manager replaced."""
        tools = await self._inner_toolset.get_tools(readonly_context)
        for tool in tools:
            if isinstance(tool, GoogleTool):
                logger.info(
                    "[AUTH-TOOLSET] Replacing _credentials_manager on tool "
                    "%r with BearerTokenCredentialsManager",
                    tool.name,
                )
                tool._credentials_manager = self._creds_manager
        logger.info(
            "[AUTH-TOOLSET] Prepared %d tool(s): %s",
            len(tools),
            [t.name for t in tools],
        )
        return tools

    async def close(self) -> None:
        """Delegate to inner toolset."""
        logger.info("[AUTH-TOOLSET] Closing inner SpannerToolset")
        await self._inner_toolset.close()
