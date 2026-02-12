"""Test the deployed ADK agent on Cloud Run via its API."""

import json
import subprocess
import requests

SERVICE_URL = "https://adk-spanner-agent-535816463745.us-central1.run.app"
APP_NAME = "spanner_agent"


def get_identity_token():
    """Get identity token for the current gcloud user."""
    result = subprocess.run(
        ["gcloud", "auth", "print-identity-token"],
        capture_output=True, text=True
    )
    return result.stdout.strip()


def create_session(token: str, user_id: str) -> str:
    """Create a new session and return session ID."""
    resp = requests.post(
        f"{SERVICE_URL}/apps/{APP_NAME}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={},
    )
    resp.raise_for_status()
    data = resp.json()
    return data["id"]


def send_message(token: str, user_id: str, session_id: str, message: str) -> dict:
    """Send a message to the agent and return the response."""
    resp = requests.post(
        f"{SERVICE_URL}/run",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "app_name": APP_NAME,
            "user_id": user_id,
            "session_id": session_id,
            "new_message": {
                "role": "user",
                "parts": [{"text": message}],
            },
            "streaming": False,
        },
    )
    resp.raise_for_status()
    return resp.json()


def main():
    token = get_identity_token()
    print(f"Using identity token (first 20 chars): {token[:20]}...")

    # Test 1: List apps
    print("\n=== Test 1: List apps ===")
    resp = requests.get(
        f"{SERVICE_URL}/list-apps",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"Apps: {resp.json()}")

    # Test 2: Create session and ask about tables
    print("\n=== Test 2: Query the agent ===")
    user_id = "test-user"
    session_id = create_session(token, user_id)
    print(f"Session created: {session_id}")

    response = send_message(
        token, user_id, session_id,
        "List all tables in the database and show me the first 3 rows from each table."
    )

    # Extract text from response events
    for event in response:
        if isinstance(event, dict):
            content = event.get("content", {})
            parts = content.get("parts", []) if isinstance(content, dict) else []
            for part in parts:
                if isinstance(part, dict) and "text" in part:
                    print(f"Agent: {part['text'][:500]}")
                if isinstance(part, dict) and "function_response" in part:
                    fr = part["function_response"]
                    print(f"Tool result ({fr.get('name', '?')}): {json.dumps(fr.get('response', {}))[:200]}")


if __name__ == "__main__":
    main()
