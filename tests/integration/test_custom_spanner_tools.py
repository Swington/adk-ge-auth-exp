"""Integration tests for ImpersonatingSpannerToolset with real Spanner.

Tests the full credential flow with actual SA impersonation against the
real Spanner database for all 3 user access levels:
- User 1 (full access): can list tables, query employees + salaries
- User 2 (no access): gets PermissionDenied on all operations
- User 3 (FGAC): can query employees, denied on salaries
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from spanner_agent.auth_wrapper import (
    USER_SA_MAP,
    ImpersonatingCredentialsManager,
)

PROJECT_ID = "switon-gsd-demos"
INSTANCE_ID = "adk-auth-exp"
DATABASE_ID = "demo-db"

USER1_EMAIL = "adk-auth-exp-1@switon.altostrat.com"
USER2_EMAIL = "adk-auth-exp-2@switon.altostrat.com"
USER3_EMAIL = "adk-auth-exp-3@switon.altostrat.com"


def _make_tool_context(user_id: str) -> MagicMock:
    ctx = MagicMock()
    ctx.user_id = user_id
    ctx.state = {}
    return ctx


class TestImpersonatedCredentialCreation(unittest.TestCase):
    """Test that impersonated credentials can be created for each user SA."""

    def setUp(self):
        self.manager = ImpersonatingCredentialsManager(USER_SA_MAP)
        self.loop = asyncio.get_event_loop()

    def test_user1_credentials_created(self):
        """Should successfully create impersonated credentials for User 1."""
        ctx = _make_tool_context(USER1_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNotNone(creds)
        self.assertEqual(
            creds.service_account_email,
            "user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
        )

    def test_user2_credentials_created(self):
        """Should successfully create impersonated credentials for User 2."""
        ctx = _make_tool_context(USER2_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNotNone(creds)
        self.assertEqual(
            creds.service_account_email,
            "user2-no-access@switon-gsd-demos.iam.gserviceaccount.com",
        )

    def test_user3_credentials_created(self):
        """Should successfully create impersonated credentials for User 3."""
        ctx = _make_tool_context(USER3_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNotNone(creds)
        self.assertEqual(
            creds.service_account_email,
            "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com",
        )


class TestUser1SpannerAccess(unittest.TestCase):
    """User 1 (full access) should be able to query all tables."""

    def setUp(self):
        from google.cloud import spanner

        self.manager = ImpersonatingCredentialsManager(USER_SA_MAP)
        self.loop = asyncio.get_event_loop()
        ctx = _make_tool_context(USER1_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        client = spanner.Client(project=PROJECT_ID, credentials=creds)
        instance = client.instance(INSTANCE_ID)
        self.database = instance.database(DATABASE_ID)

    def test_can_read_employees(self):
        with self.database.snapshot() as snapshot:
            results = list(
                snapshot.execute_sql("SELECT * FROM employees LIMIT 1")
            )
            self.assertGreaterEqual(len(results), 0)

    def test_can_read_salaries(self):
        with self.database.snapshot() as snapshot:
            results = list(
                snapshot.execute_sql("SELECT * FROM salaries LIMIT 1")
            )
            self.assertGreaterEqual(len(results), 0)


class TestUser2SpannerAccess(unittest.TestCase):
    """User 2 (no access) should fail on all operations."""

    def setUp(self):
        from google.cloud import spanner

        self.manager = ImpersonatingCredentialsManager(USER_SA_MAP)
        self.loop = asyncio.get_event_loop()
        ctx = _make_tool_context(USER2_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        client = spanner.Client(project=PROJECT_ID, credentials=creds)
        instance = client.instance(INSTANCE_ID)
        self.database = instance.database(DATABASE_ID)

    def test_cannot_query(self):
        from google.api_core.exceptions import PermissionDenied

        with self.assertRaises(PermissionDenied):
            with self.database.snapshot() as snapshot:
                list(
                    snapshot.execute_sql("SELECT * FROM employees LIMIT 1")
                )


class TestUser3SpannerAccess(unittest.TestCase):
    """User 3 (FGAC) can read employees but not salaries."""

    def setUp(self):
        from google.cloud import spanner

        self.manager = ImpersonatingCredentialsManager(USER_SA_MAP)
        self.loop = asyncio.get_event_loop()
        ctx = _make_tool_context(USER3_EMAIL)
        creds = self.loop.run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        client = spanner.Client(project=PROJECT_ID, credentials=creds)
        instance = client.instance(INSTANCE_ID)
        self.database = instance.database(
            DATABASE_ID, database_role="employees_reader"
        )

    def test_can_read_employees(self):
        with self.database.snapshot() as snapshot:
            results = list(
                snapshot.execute_sql("SELECT * FROM employees LIMIT 1")
            )
            self.assertGreaterEqual(len(results), 0)

    def test_cannot_read_salaries(self):
        from google.api_core.exceptions import PermissionDenied

        with self.assertRaises(PermissionDenied):
            with self.database.snapshot() as snapshot:
                list(
                    snapshot.execute_sql("SELECT * FROM salaries LIMIT 1")
                )


if __name__ == "__main__":
    unittest.main()
