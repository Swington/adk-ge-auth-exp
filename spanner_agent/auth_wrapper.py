"""Bearer token credential propagation for SpannerToolset.

When Gemini Enterprise invokes the agent via A2A, it includes the end-user's
OAuth access token in the HTTP Authorization header (Bearer <token>).  This
module:

1.  Provides ASGI middleware (AuthTokenExtractorMiddleware) that extracts the
    Bearer token and stores it in a contextvars.ContextVar so it is visible
    anywhere in the same async call-chain.

2.  Provides BearerTokenCredentialsManager — a drop-in replacement for
    GoogleCredentialsManager — that reads the token from the ContextVar and
    returns google.oauth2.credentials.Credentials(token=...).

3.  Provides BearerTokenSpannerToolset — a BaseToolset wrapper that creates an
    inner SpannerToolset and replaces _credentials_manager on every GoogleTool
    with the BearerTokenCredentialsManager.

Every step is logged so the pipeline can be traced end-to-end:
    [AUTH-MIDDLEWARE] → [AUTH-CREDS] → [AUTH-TOOLSET]
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any, List, Optional, Union

import google.auth
import google.oauth2.credentials
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset, ToolPredicate
from google.adk.tools.google_tool import GoogleTool
from google.adk.tools.spanner.settings import SpannerToolSettings
from google.adk.tools.spanner.spanner_toolset import SpannerToolset

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ContextVar: holds the Bearer token for the current request
# ---------------------------------------------------------------------------
_current_bearer_token: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("bearer_token", default=None)
)


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
    """ASGI middleware that pulls the Bearer token from the Authorization header.

    Stores the token in ``_current_bearer_token`` so downstream code (running
    in the same async context) can access it via ``get_bearer_token()``.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # ASGI headers are [(name_bytes, value_bytes), …]
        headers = dict(scope.get("headers", []))
        auth_value = headers.get(b"authorization", b"").decode()

        if auth_value.lower().startswith("bearer "):
            token = auth_value[7:]
            logger.info(
                "[AUTH-MIDDLEWARE] Extracted Bearer token from Authorization "
                "header (length=%d, first_20_chars=%s…)",
                len(token),
                token[:20],
            )
            reset = set_bearer_token(token)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_bearer_token.reset(reset)
        else:
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
