"""Bearer token credential propagation for SpannerToolset.

When Gemini Enterprise invokes the agent via A2A, it includes the end-user's
OAuth access token.  On Cloud Run (where ``Authorization`` is consumed by
Cloud Run's own IAM check), the token arrives in ``X-User-Authorization``.

Header priority (first match wins):
    1. ``X-User-Authorization: Bearer <token>``   – Cloud Run
    2. ``Authorization: Bearer <token>``           – local / direct calls

Components:

1.  **AuthTokenExtractorMiddleware** — ASGI middleware that extracts the Bearer
    token and stores it in a ``contextvars.ContextVar``.

2.  **BearerTokenCredentialsManager** — drop-in replacement for ADK's
    ``GoogleCredentialsManager``; reads the token from the ContextVar and
    returns ``google.oauth2.credentials.Credentials(token=...)``.

3.  **BearerTokenSpannerToolset** — ``BaseToolset`` wrapper that creates an
    inner ``SpannerToolset`` and replaces ``_credentials_manager`` on every
    ``GoogleTool`` with ``BearerTokenCredentialsManager``.

4.  **FGAC database-role injection** — monkey-patches
    ``Instance.database()`` so that the Spanner ``database_role`` parameter
    is automatically set based on the user's email (resolved from the OAuth
    token via the Google tokeninfo / userinfo APIs).
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
# Maps user email (or SA email) to the Spanner database role they should
# assume.  Users not in this map connect without a database role, so standard
# IAM access applies.
USER_DATABASE_ROLE_MAP: Dict[str, str] = {
    # Workspace user (Gemini Enterprise OAuth flow)
    "adk-auth-exp-3@switon.altostrat.com": "employees_reader",
    # Service account (integration tests via SA impersonation)
    "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com": "employees_reader",
}

# ---------------------------------------------------------------------------
# ContextVars — per-request state visible across the async call-chain
# ---------------------------------------------------------------------------
_current_bearer_token: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("bearer_token", default=None)
)
_current_database_role: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("database_role", default=None)
)


def _resolve_user_email(token: str) -> Optional[str]:
    """Resolve the user's email from an OAuth access token.

    Tries Google's ``tokeninfo`` endpoint first, then falls back to
    ``userinfo``.  Returns ``None`` if the email cannot be determined
    (e.g. the token lacks the ``email`` scope).
    """
    # 1. tokeninfo — works when the token includes the email scope
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"access_token": token},
            timeout=5.0,
        )
        if resp.status_code == 200:
            email = resp.json().get("email")
            if email:
                logger.info("[AUTH] Resolved email=%s via tokeninfo", email)
                return email
        elif resp.status_code != 400:
            logger.debug("[AUTH] tokeninfo returned status=%d", resp.status_code)
    except Exception as exc:
        logger.debug("[AUTH] tokeninfo call failed: %s", exc)

    # 2. userinfo — works when the token includes email or openid scope
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            email = resp.json().get("email")
            if email:
                logger.info("[AUTH] Resolved email=%s via userinfo", email)
                return email
    except Exception as exc:
        logger.debug("[AUTH] userinfo call failed: %s", exc)

    logger.warning("[AUTH] Could not resolve email from token")
    return None


# ---------------------------------------------------------------------------
# Monkey-patch Instance.database() to inject database_role from ContextVar
# ---------------------------------------------------------------------------
_Instance = google.cloud.spanner_v1.instance.Instance
_original_instance_database = _Instance.database


def _patched_instance_database(self, database_id, *args, **kwargs):
    """Wrapper that injects ``database_role`` from the ContextVar."""
    db_role = _current_database_role.get()
    if db_role and "database_role" not in kwargs:
        logger.info(
            "[AUTH] Injecting database_role=%r for database=%s",
            db_role,
            database_id,
        )
        kwargs["database_role"] = db_role
    return _original_instance_database(self, database_id, *args, **kwargs)


_Instance.database = _patched_instance_database


def get_bearer_token() -> Optional[str]:
    """Return the Bearer token for the current async context, or ``None``."""
    return _current_bearer_token.get()


def set_bearer_token(token: Optional[str]) -> contextvars.Token:
    """Set the Bearer token for the current async context."""
    return _current_bearer_token.set(token)


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------
class AuthTokenExtractorMiddleware:
    """ASGI middleware that extracts the end-user's Bearer token.

    Checks ``X-User-Authorization`` first (Cloud Run), then falls back to
    ``Authorization``.  Stores the token in a ContextVar so downstream code
    can retrieve it via :func:`get_bearer_token`.

    Also resolves the user's email from the token and sets the FGAC
    ``database_role`` ContextVar when the email appears in
    :data:`USER_DATABASE_ROLE_MAP`.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    @staticmethod
    def _extract_bearer(headers: dict[bytes, bytes]) -> tuple[str | None, str]:
        """Return ``(token, source_header)`` or ``(None, "")``."""
        for header, name in [
            (b"x-user-authorization", "X-User-Authorization"),
            (b"authorization", "Authorization"),
        ]:
            value = headers.get(header, b"").decode()
            if value.lower().startswith("bearer "):
                return value[7:], name
        return None, ""

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        token, source = self._extract_bearer(headers)

        if not token:
            await self.app(scope, receive, send)
            return

        logger.info("[AUTH] Bearer token from %s (length=%d)", source, len(token))
        reset_token = set_bearer_token(token)

        # Resolve user email → FGAC database role
        db_role = None
        email = _resolve_user_email(token)
        if email:
            db_role = USER_DATABASE_ROLE_MAP.get(email)
            if db_role:
                logger.info("[AUTH] %s → database_role=%s", email, db_role)
        reset_role = _current_database_role.set(db_role)

        try:
            await self.app(scope, receive, send)
        finally:
            _current_bearer_token.reset(reset_token)
            _current_database_role.reset(reset_role)


# ---------------------------------------------------------------------------
# Credentials manager (duck-types GoogleCredentialsManager)
# ---------------------------------------------------------------------------
class BearerTokenCredentialsManager:
    """Returns ``google.oauth2.credentials.Credentials`` from the ContextVar.

    If no token is present, returns ``None`` — which causes
    ``GoogleTool.run_async`` to return an "authorization required" message.
    """

    async def get_valid_credentials(
        self, tool_context: Any
    ) -> Optional[google.oauth2.credentials.Credentials]:
        token = get_bearer_token()
        if not token:
            logger.warning("[AUTH] No Bearer token available for Spanner call")
            return None
        return google.oauth2.credentials.Credentials(token=token)


# ---------------------------------------------------------------------------
# Toolset wrapper
# ---------------------------------------------------------------------------
class BearerTokenSpannerToolset(BaseToolset):
    """Wraps ``SpannerToolset`` so every ``GoogleTool`` uses the Bearer token.

    Replaces ``_credentials_manager`` on each tool with a
    :class:`BearerTokenCredentialsManager` that reads the per-request token
    from the ContextVar.
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
        # the credentials are never used because _credentials_manager is
        # replaced on every tool.
        from google.adk.tools.spanner.spanner_credentials import (
            SpannerCredentialsConfig,
        )

        adc_creds, _ = google.auth.default()
        self._inner_toolset = SpannerToolset(
            credentials_config=SpannerCredentialsConfig(credentials=adc_creds),
            spanner_tool_settings=spanner_tool_settings,
            tool_filter=tool_filter,
        )

    async def get_tools(
        self, readonly_context: Optional[ReadonlyContext] = None
    ) -> List[BaseTool]:
        """Get tools from the inner toolset with credentials replaced."""
        tools = await self._inner_toolset.get_tools(readonly_context)
        for tool in tools:
            if isinstance(tool, GoogleTool):
                tool._credentials_manager = self._creds_manager
        logger.info(
            "[AUTH] Prepared %d tool(s): %s",
            len(tools),
            [t.name for t in tools],
        )
        return tools

    async def close(self) -> None:
        """Delegate to the inner toolset."""
        await self._inner_toolset.close()
