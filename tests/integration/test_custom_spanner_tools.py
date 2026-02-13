"""Integration tests for Bearer token credential flow with real Spanner.

These tests require:
- ADC with permissions to access the Spanner database
- The Spanner instance/database to exist

They verify that google.oauth2.credentials.Credentials(token=...)
can be used to authenticate Spanner operations when given a valid
access token.
"""

import asyncio
import unittest
from unittest.mock import MagicMock

import google.auth
import google.auth.transport.requests
from google.cloud import spanner

PROJECT_ID = "switon-gsd-demos"
INSTANCE_ID = "adk-auth-exp"
DATABASE_ID = "demo-db"


def _get_adc_access_token() -> str:
    """Get a fresh access token from ADC for testing."""
    creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)
    return creds.token


class TestBearerTokenWithSpanner(unittest.TestCase):
    """Test that a Bearer token can be used to access Spanner."""

    def setUp(self):
        self.token = _get_adc_access_token()

    def test_bearer_token_credentials_can_query_spanner(self):
        """A Bearer token wrapped in Credentials should work with Spanner."""
        import google.oauth2.credentials

        creds = google.oauth2.credentials.Credentials(token=self.token)
        client = spanner.Client(project=PROJECT_ID, credentials=creds)
        instance = client.instance(INSTANCE_ID)
        database = instance.database(DATABASE_ID)

        with database.snapshot() as snapshot:
            results = list(
                snapshot.execute_sql("SELECT 1 AS test_col")
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0][0], 1)


if __name__ == "__main__":
    unittest.main()
