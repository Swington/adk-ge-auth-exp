"""Custom server entry point for Cloud Run deployment.

Wraps the ADK web server with AuthTokenExtractorMiddleware so the
Bearer token sent by Gemini Enterprise (in the HTTP Authorization
header) is available to the Spanner tools via a ContextVar.

Usage (Cloud Run):
    uvicorn main:app --host 0.0.0.0 --port $PORT

Usage (local testing):
    uv run uvicorn main:app --host 127.0.0.1 --port 8080
"""

import logging

from google.adk.cli.fast_api import get_fast_api_app

from spanner_agent.auth_wrapper import AuthTokenExtractorMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

inner_app = get_fast_api_app(
    agents_dir=".",
    web=False,
    a2a=True,
)

# Wrap with ASGI middleware that extracts the Bearer token from
# the Authorization header and stores it in a ContextVar.
app = AuthTokenExtractorMiddleware(inner_app)

logger.info("[MAIN] App created with AuthTokenExtractorMiddleware")
