"""Custom server entry point with Bearer token middleware.

Wraps the ADK web server with AuthTokenExtractorMiddleware so the
Bearer token sent by Gemini Enterprise (in the HTTP Authorization
header) is available to the Spanner tools via a ContextVar.

Also rewrites root-path requests to the A2A endpoint because Gemini
Enterprise posts to ``/`` while the ADK mounts the A2A handler at
``/a2a/spanner_agent``.

Usage (Cloud Run):
    uvicorn main:app --host 0.0.0.0 --port $PORT

Usage (local testing):
    uv run uvicorn main:app --host 127.0.0.1 --port 8080
"""

import logging
from typing import Any

from google.adk.cli.fast_api import get_fast_api_app

from spanner_agent.auth_wrapper import AuthTokenExtractorMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

A2A_AGENT_PATH = "/a2a/spanner_agent"


# ---------------------------------------------------------------------------
# URL rewriting middleware: / → /a2a/spanner_agent
# ---------------------------------------------------------------------------
class RootToA2ARewriteMiddleware:
    """Rewrites root-path requests to the A2A agent endpoint.

    Gemini Enterprise sends POST to ``/`` but ADK mounts the A2A handler
    at ``/a2a/spanner_agent``.  This middleware rewrites the ASGI scope
    so the request reaches the correct handler.

    Also rewrites ``/.well-known/agent-card.json`` to the A2A agent card
    path for agent discovery.
    """

    REWRITE_MAP = {
        "/": A2A_AGENT_PATH,
        "/.well-known/agent-card.json": f"{A2A_AGENT_PATH}/.well-known/agent-card.json",
    }

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            original_path = scope.get("path", "")
            rewritten = self.REWRITE_MAP.get(original_path)
            if rewritten:
                logger.info(
                    "[URL-REWRITE] %s %s → %s",
                    scope.get("method", "?"),
                    original_path,
                    rewritten,
                )
                scope = dict(scope, path=rewritten, raw_path=rewritten.encode())
        await self.app(scope, receive, send)


inner_app = get_fast_api_app(
    agents_dir=".",
    web=True,
    a2a=True,
)

# Middleware chain (outermost first):
# 1. AuthTokenExtractorMiddleware — extract Bearer token
# 2. RootToA2ARewriteMiddleware   — rewrite / → /a2a/spanner_agent
# 3. inner_app (FastAPI)
app = AuthTokenExtractorMiddleware(RootToA2ARewriteMiddleware(inner_app))

logger.info("[MAIN] App created with auth + URL-rewrite middleware")
