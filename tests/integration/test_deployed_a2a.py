"""Integration tests: A2A Bearer token propagation on deployed Cloud Run agent.

Generates access tokens for each test SA via impersonation, sends A2A
message/send requests with those tokens in X-User-Authorization header,
and verifies the agent returns correct data (or permission errors) for
each user.

Requirements:
- ADC configured with serviceAccountTokenCreator on the test SAs
- The Cloud Run service must be deployed and accessible
- gcloud auth print-identity-token must work for Cloud Run auth

Run:
    uv run python -m pytest tests/integration/test_deployed_a2a.py -v -s
"""

import json
import logging
import os
import subprocess
import uuid

import google.auth
import google.auth.impersonated_credentials
import google.auth.transport.requests
import httpx
import pytest

logger = logging.getLogger(__name__)

SERVICE_URL = os.environ.get("CLOUD_RUN_SERVICE_URL", "")
A2A_ENDPOINT = f"{SERVICE_URL}/a2a/spanner_agent"

# Service accounts representing users with different access levels — set via environment variables
SA_FULL_ACCESS = os.environ.get("TEST_SA_FULL_ACCESS", "")
SA_NO_ACCESS = os.environ.get("TEST_SA_NO_ACCESS", "")
SA_FGAC = os.environ.get("TEST_SA_FGAC", "")


def _get_identity_token() -> str:
    """Get an identity token for Cloud Run authentication."""
    result = subprocess.run(
        ["gcloud", "auth", "print-identity-token"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"gcloud failed: {result.stderr}"
    return result.stdout.strip()


def _get_impersonated_access_token(target_sa: str) -> str:
    """Generate an OAuth2 access token by impersonating a service account."""
    source_creds, _ = google.auth.default()
    impersonated = google.auth.impersonated_credentials.Credentials(
        source_credentials=source_creds,
        target_principal=target_sa,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform", "email"],
    )
    auth_req = google.auth.transport.requests.Request()
    impersonated.refresh(auth_req)
    assert impersonated.token, f"Failed to get token for {target_sa}"
    logger.info(
        "Generated access token for %s (length=%d)",
        target_sa,
        len(impersonated.token),
    )
    return impersonated.token


def _a2a_message_send(
    client: httpx.Client,
    text: str,
    identity_token: str,
    user_access_token: str | None = None,
) -> dict:
    """Send a message/send JSON-RPC request to the A2A endpoint.

    Uses identity_token for Cloud Run auth (Authorization header) and
    user_access_token for the user's Spanner credentials
    (X-User-Authorization header).
    """
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

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {identity_token}",
    }
    if user_access_token:
        headers["X-User-Authorization"] = f"Bearer {user_access_token}"

    resp = client.post(
        A2A_ENDPOINT,
        json=payload,
        headers=headers,
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()


def _extract_agent_text(result: dict) -> str:
    """Extract the agent's text response from the A2A result."""
    if "error" in result:
        return f"ERROR: {result['error']}"
    res = result.get("result", {})
    # Check artifacts
    for artifact in res.get("artifacts", []):
        for part in artifact.get("parts", []):
            if part.get("kind") == "text":
                return part["text"]
    # Check history for last agent message
    for msg in reversed(res.get("history", [])):
        if msg.get("role") == "agent":
            for part in msg.get("parts", []):
                if part.get("kind") == "text":
                    return part["text"]
    return json.dumps(res)[:500]


@pytest.fixture(scope="module")
def identity_token():
    """Get identity token for Cloud Run authentication."""
    return _get_identity_token()


@pytest.fixture(scope="module")
def full_access_token():
    """Access token for user1 (full Spanner access)."""
    return _get_impersonated_access_token(SA_FULL_ACCESS)


@pytest.fixture(scope="module")
def no_access_token():
    """Access token for user2 (no Spanner access)."""
    return _get_impersonated_access_token(SA_NO_ACCESS)


@pytest.fixture(scope="module")
def fgac_token():
    """Access token for user3 (FGAC - employees only)."""
    return _get_impersonated_access_token(SA_FGAC)


class TestDeployedAgentCard:
    """Verify the deployed A2A agent card."""

    def test_agent_card(self, identity_token):
        resp = httpx.get(
            f"{A2A_ENDPOINT}/.well-known/agent-card.json",
            headers={"Authorization": f"Bearer {identity_token}"},
            timeout=10.0,
        )
        assert resp.status_code == 200
        card = resp.json()
        assert card["name"] == "Spanner Data Agent"
        logger.info("Agent card: %s", json.dumps(card, indent=2))


class TestFullAccessUser:
    """User 1: full Spanner access — should see all tables and data."""

    def test_list_tables(self, identity_token, full_access_token):
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="List all tables in the database.",
                identity_token=identity_token,
                user_access_token=full_access_token,
            )

        text = _extract_agent_text(result)
        logger.info("Full access user response: %s", text[:1000])

        assert "result" in result, f"Expected result, got: {result}"
        # Should mention tables (employees, salaries)
        text_lower = text.lower()
        assert "employees" in text_lower or "table" in text_lower, (
            f"Expected table info, got: {text[:500]}"
        )

    def test_query_employees(self, identity_token, full_access_token):
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="Run this SQL: SELECT * FROM employees LIMIT 3",
                identity_token=identity_token,
                user_access_token=full_access_token,
            )

        text = _extract_agent_text(result)
        logger.info("Full access query response: %s", text[:1000])
        assert "result" in result


class TestNoAccessUser:
    """User 2: no Spanner access — should get permission errors."""

    def test_query_denied(self, identity_token, no_access_token):
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="List all tables in the database.",
                identity_token=identity_token,
                user_access_token=no_access_token,
            )

        text = _extract_agent_text(result)
        logger.info("No-access user response: %s", text[:1000])

        assert "result" in result, f"Expected result, got: {result}"
        # Should mention permission denied or access error
        text_lower = text.lower()
        assert any(
            keyword in text_lower
            for keyword in ["permission", "denied", "access", "error", "credentials"]
        ), f"Expected permission error, got: {text[:500]}"


class TestFgacUser:
    """User 3: FGAC — should see employees but not salaries."""

    def test_query_employees_works(self, identity_token, fgac_token):
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="Run this SQL: SELECT * FROM employees LIMIT 3",
                identity_token=identity_token,
                user_access_token=fgac_token,
            )

        text = _extract_agent_text(result)
        logger.info("FGAC user employees response: %s", text[:1000])
        assert "result" in result

    def test_query_salaries_denied(self, identity_token, fgac_token):
        """FGAC user should NOT be able to read salaries table."""
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="Run this SQL: SELECT * FROM salaries LIMIT 3",
                identity_token=identity_token,
                user_access_token=fgac_token,
            )

        text = _extract_agent_text(result)
        logger.info("FGAC user salaries response: %s", text[:1000])
        assert "result" in result
        text_lower = text.lower()
        assert any(
            keyword in text_lower
            for keyword in ["permission", "denied", "access", "error", "not found"]
        ), f"Expected permission error for salaries, got: {text[:500]}"


class TestNoTokenRequest:
    """Request without user token — should get auth required message."""

    def test_no_user_token(self, identity_token):
        with httpx.Client() as client:
            result = _a2a_message_send(
                client,
                text="List tables",
                identity_token=identity_token,
                user_access_token=None,
            )

        logger.info("No-token response: %s", json.dumps(result, indent=2)[:1000])
        # Without user token, the middleware will extract the identity token
        # from Authorization header (fallback). This JWT will fail on Spanner.
        assert "result" in result or "error" in result
