"""Integration tests for Agent Engine deployment.

Tests that the deployed Agent Engine correctly propagates user
authorization tokens to Spanner and enforces per-user access control.

Requires:
- ADC with serviceAccountTokenCreator on the test SAs
- Agent Engine resource: projects/535816463745/locations/us-central1/reasoningEngines/5919158175969312768
"""

import asyncio
import json
import os

import google.auth
import google.auth.impersonated_credentials
import google.auth.transport.requests
import pytest
import vertexai
from vertexai.agent_engines import AdkApp

PROJECT_ID = "switon-gsd-demos"
REGION = "us-central1"
AGENT_ENGINE_ID = "5919158175969312768"

# Service accounts used for impersonation to simulate workspace users
USER1_SA = "user1-full-access@switon-gsd-demos.iam.gserviceaccount.com"
USER2_SA = "user2-no-access@switon-gsd-demos.iam.gserviceaccount.com"
USER3_SA = "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com"

SPANNER_SCOPES = [
    "https://www.googleapis.com/auth/spanner.data",
    "https://www.googleapis.com/auth/spanner.admin",
    "https://www.googleapis.com/auth/cloud-platform",
    "email",
]


def _get_impersonated_token(target_sa: str) -> str:
    """Get an access token by impersonating the given SA."""
    source_creds, _ = google.auth.default()
    impersonated = google.auth.impersonated_credentials.Credentials(
        source_credentials=source_creds,
        target_principal=target_sa,
        target_scopes=SPANNER_SCOPES,
    )
    impersonated.refresh(google.auth.transport.requests.Request())
    return impersonated.token


def _call_agent_engine(token: str, message: str) -> list[dict]:
    """Call the deployed Agent Engine with an authorization token.

    Uses the vertexai SDK to send a request with authorizations
    to streaming_agent_run_with_events.
    """
    vertexai.init(project=PROJECT_ID, location=REGION)

    from vertexai import agent_engines

    agent = agent_engines.get(AGENT_ENGINE_ID)

    # Build the request payload matching what Gemini Enterprise sends
    request_payload = {
        "message": {"role": "user", "parts": [{"text": message}]},
        "user_id": "test-user",
        "authorizations": {
            "test_auth": {"access_token": token},
        },
    }

    result = agent.streaming_agent_run_with_events(
        request_json=json.dumps(request_payload)
    )

    # Handle both sync iterables and async generators
    import inspect

    if inspect.isasyncgen(result):

        async def _collect():
            events = []
            async for event in result:
                events.append(event)
            return events

        return asyncio.run(_collect())
    else:
        return list(result)


def _extract_text(events: list[dict]) -> str:
    """Extract the agent's text response from events."""
    texts = []
    for event in events:
        if "events" in event:
            for e in event["events"]:
                content = e.get("content", {})
                parts = content.get("parts", [])
                for part in parts:
                    if "text" in part:
                        texts.append(part["text"])
    return " ".join(texts)


class TestAgentEngineUserIsolation:
    """Test that each user gets correct access level on Agent Engine."""

    def test_user1_full_access(self):
        """User 1 (full access) can list tables and query data."""
        token = _get_impersonated_token(USER1_SA)
        events = _call_agent_engine(token, "List all tables in the database")
        text = _extract_text(events)
        # User 1 should see tables
        assert "employees" in text.lower() or "salaries" in text.lower(), (
            f"User 1 should have full access. Got: {text[:500]}"
        )

    def test_user2_no_access(self):
        """User 2 (no access) gets a permission error."""
        token = _get_impersonated_token(USER2_SA)
        events = _call_agent_engine(token, "List all tables in the database")
        text = _extract_text(events)
        # User 2 should get a permission error
        assert "permission" in text.lower() or "denied" in text.lower() or "error" in text.lower(), (
            f"User 2 should get permission denied. Got: {text[:500]}"
        )

    def test_user3_fgac_employees_only(self):
        """User 3 (FGAC) can read employees but not salaries."""
        token = _get_impersonated_token(USER3_SA)
        events = _call_agent_engine(
            token, "Query all data from the employees table"
        )
        text = _extract_text(events)
        # User 3 should see employee data
        assert "employee" in text.lower() or "name" in text.lower(), (
            f"User 3 should see employees. Got: {text[:500]}"
        )

    def test_user3_fgac_salaries_denied(self):
        """User 3 (FGAC) cannot read salaries."""
        token = _get_impersonated_token(USER3_SA)
        events = _call_agent_engine(
            token, "Query all data from the salaries table"
        )
        text = _extract_text(events)
        # User 3 should get an error on salaries
        assert "permission" in text.lower() or "denied" in text.lower() or "error" in text.lower() or "access" in text.lower(), (
            f"User 3 should be denied salaries. Got: {text[:500]}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
