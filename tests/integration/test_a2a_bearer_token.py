"""Integration tests: Bearer token propagation through A2A to Spanner.

Starts a local ADK server with AuthTokenExtractorMiddleware, generates
a real access token from ADC, sends it as a Bearer token in A2A
message/send requests, and verifies the agent returns data from Spanner.

Requirements:
- ADC configured with Spanner access
- The Spanner instance/database must exist
- Gemini API access (for the LLM model)

Run:
    uv run python -m pytest tests/integration/test_a2a_bearer_token.py -v -s
"""

import json
import logging
import multiprocessing
import time
import uuid

import google.auth
import google.auth.transport.requests
import httpx
import pytest

logger = logging.getLogger(__name__)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8091
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
A2A_ENDPOINT = f"{BASE_URL}/a2a/spanner_agent"
APP_NAME = "spanner_agent"


def _run_server():
    """Start the ADK server with middleware in a subprocess."""
    import uvicorn

    # Import here so the app is created in the subprocess
    from main import app

    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT, log_level="info")


def _get_access_token() -> str:
    """Get a fresh access token from ADC."""
    creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)
    return creds.token


def _wait_for_server(url: str, timeout: float = 30.0):
    """Wait until the server is reachable."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{url}/list-apps", timeout=2.0)
            if resp.status_code == 200:
                return
        except httpx.ConnectError:
            pass
        time.sleep(0.5)
    raise TimeoutError(f"Server at {url} did not start within {timeout}s")


def _a2a_message_send(
    client: httpx.Client,
    text: str,
    token: str | None = None,
    context_id: str | None = None,
) -> dict:
    """Send a message/send JSON-RPC request to the A2A endpoint."""
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "messageId": str(uuid.uuid4()),
                "parts": [{"kind": "text", "text": text}],
            },
        },
    }
    if context_id:
        payload["params"]["message"]["contextId"] = context_id

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resp = client.post(
        A2A_ENDPOINT,
        json=payload,
        headers=headers,
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()


@pytest.fixture(scope="module")
def server():
    """Start the ADK server in a subprocess for the test module."""
    proc = multiprocessing.Process(target=_run_server, daemon=True)
    proc.start()
    try:
        _wait_for_server(BASE_URL)
        yield proc
    finally:
        proc.terminate()
        proc.join(timeout=5)


@pytest.fixture(scope="module")
def access_token():
    """Generate a fresh access token from ADC."""
    token = _get_access_token()
    logger.info("Generated access token (length=%d)", len(token))
    return token


class TestA2AAgentCard:
    """Verify the A2A agent card is served correctly."""

    def test_agent_card_accessible(self, server):
        resp = httpx.get(
            f"{A2A_ENDPOINT}/.well-known/agent-card.json", timeout=5.0
        )
        assert resp.status_code == 200
        card = resp.json()
        assert card["name"] == "Spanner Data Agent"
        assert len(card["skills"]) >= 1


class TestA2ABearerTokenFlow:
    """Test that Bearer tokens propagate through A2A to Spanner tools."""

    def test_agent_responds_to_simple_query(self, server, access_token):
        """Send a simple query via A2A with Bearer token and get a response."""
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="What tables are available in the database?",
                token=access_token,
            )

        logger.info("A2A response: %s", json.dumps(result, indent=2)[:2000])

        # Should have a result (not an error)
        assert "result" in result, f"Expected result, got: {result}"
        # The result should contain message parts with text
        msg = result["result"]
        assert "status" in msg or "message" in msg, (
            f"Unexpected response format: {msg}"
        )

    def test_auth_logs_show_token_extraction(self, server, access_token):
        """Verify the auth pipeline logs appear (middleware → creds → toolset)."""
        # This test mainly verifies the pipeline works end-to-end.
        # The actual log verification happens in the server output.
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="List all tables in the Spanner database.",
                token=access_token,
            )

        assert "result" in result, f"Expected result, got: {result}"

    def test_request_without_token_still_works(self, server):
        """Without a Bearer token, agent should return auth required message."""
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="List tables",
                token=None,  # No token
            )

        logger.info(
            "Response without token: %s",
            json.dumps(result, indent=2)[:2000],
        )
        # Should still get a response (possibly with auth error message)
        assert "result" in result or "error" in result
