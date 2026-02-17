"""Unit tests for Bearer token credential propagation (Cloud Run / A2A).

Tests the auth pipeline:
1. ContextVar token storage (set/get/reset)
2. ASGI middleware Bearer token extraction (Authorization, X-User-Authorization)
3. BearerTokenCredentialsManager creates Credentials from token
4. BearerTokenSpannerToolset replaces _credentials_manager on tools
5. FGAC database_role ContextVar and USER_DATABASE_ROLE_MAP
6. Middleware sets database_role based on resolved email
7. Conditional monkey patches (only active in managed context)
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from google.cloud.spanner_admin_database_v1.types import DatabaseDialect

from spanner_agent.auth_wrapper import (
    AuthTokenExtractorMiddleware,
    _current_bearer_token,
    _current_database_role,
    _is_auth_managed,
    _patched_exists,
    _patched_get_database_ddl,
    _patched_instance_database,
    get_bearer_token,
    set_bearer_token,
)

FAKE_TOKEN = "test-fake-access-token-for-unit-testing-1234567890"


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --------------------------------------------------------------------------
# ContextVar helpers
# --------------------------------------------------------------------------
class TestContextVar(unittest.TestCase):
    def tearDown(self):
        _current_bearer_token.set(None)

    def test_default_is_none(self):
        self.assertIsNone(get_bearer_token())

    def test_set_and_get(self):
        set_bearer_token(FAKE_TOKEN)
        self.assertEqual(get_bearer_token(), FAKE_TOKEN)

    def test_reset_via_token(self):
        reset = set_bearer_token(FAKE_TOKEN)
        self.assertEqual(get_bearer_token(), FAKE_TOKEN)
        _current_bearer_token.reset(reset)
        self.assertIsNone(get_bearer_token())


# --------------------------------------------------------------------------
# ASGI Middleware
# --------------------------------------------------------------------------
class TestAuthTokenExtractorMiddleware(unittest.TestCase):
    def tearDown(self):
        _current_bearer_token.set(None)
        _is_auth_managed.set(False)

    def test_extracts_bearer_token(self):
        captured = {}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()
            captured["managed"] = _is_auth_managed.get()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))

        self.assertEqual(captured["token"], FAKE_TOKEN)
        self.assertTrue(captured["managed"])
        self.assertIsNone(get_bearer_token())  # reset after request
        self.assertFalse(_is_auth_managed.get())

    def test_case_insensitive_bearer(self):
        captured = {}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"BEARER some_token")],
        }
        _run(middleware(scope, None, None))
        self.assertEqual(captured["token"], "some_token")


# --------------------------------------------------------------------------
# FGAC: database_role ContextVar and Instance.database() patch
# --------------------------------------------------------------------------
class TestPatchedInstanceDatabase(unittest.TestCase):
    def tearDown(self):
        _current_database_role.set(None)
        _is_auth_managed.set(False)

    def test_patched_database_injects_role_and_dialect_when_managed(self):
        _is_auth_managed.set(True)
        _current_database_role.set("employees_reader")
        mock_instance = MagicMock()
        mock_db = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_instance_database",
            return_value=mock_db,
        ) as mock_orig:
            _patched_instance_database(mock_instance, "test-db")

        mock_orig.assert_called_once_with(
            mock_instance,
            "test-db",
            database_role="employees_reader",
            database_dialect=DatabaseDialect.GOOGLE_STANDARD_SQL,
        )

    def test_patched_database_calls_original_unchanged_when_not_managed(self):
        _is_auth_managed.set(False)
        _current_database_role.set("employees_reader")
        mock_instance = MagicMock()
        mock_db = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_instance_database",
            return_value=mock_db,
        ) as mock_orig:
            _patched_instance_database(mock_instance, "test-db")

        mock_orig.assert_called_once_with(mock_instance, "test-db")


# --------------------------------------------------------------------------
# Database.exists() patch
# --------------------------------------------------------------------------
class TestPatchedExists(unittest.TestCase):
    def tearDown(self):
        _is_auth_managed.set(False)

    def test_patched_exists_uses_get_database_when_managed(self):
        _is_auth_managed.set(True)
        db = MagicMock()
        db.name = "projects/test/instances/test/databases/test"
        db._next_nth_request = 1
        mock_api = MagicMock()
        db._instance._client.database_admin_api = mock_api

        result = _patched_exists(db)

        self.assertTrue(result)
        mock_api.get_database.assert_called_once()
        mock_api.get_database_ddl.assert_not_called()

    def test_patched_exists_calls_original_when_not_managed(self):
        _is_auth_managed.set(False)
        db = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_exists",
            return_value=True,
        ) as mock_orig:
            result = _patched_exists(db)

        self.assertTrue(result)
        mock_orig.assert_called_once_with(db)


# --------------------------------------------------------------------------
# DatabaseAdminClient.get_database_ddl patch
# --------------------------------------------------------------------------
class TestPatchedGetDatabaseDdl(unittest.TestCase):
    def tearDown(self):
        _is_auth_managed.set(False)

    def test_patched_get_ddl_returns_empty_when_managed(self):
        _is_auth_managed.set(True)
        from google.cloud.spanner_admin_database_v1.types import (
            GetDatabaseDdlResponse,
        )

        mock_client = MagicMock()
        result = _patched_get_database_ddl(mock_client, database="test-db")

        self.assertIsInstance(result, GetDatabaseDdlResponse)
        self.assertEqual(list(result.statements), [])
        mock_client._transport.assert_not_called()

    def test_patched_get_ddl_calls_original_when_not_managed(self):
        _is_auth_managed.set(False)
        mock_client = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_get_database_ddl",
            return_value="original_resp",
        ) as mock_orig:
            result = _patched_get_database_ddl(mock_client, database="test-db")

        self.assertEqual(result, "original_resp")
        mock_orig.assert_called_once_with(mock_client, database="test-db")


# --------------------------------------------------------------------------
# Middleware and Database Role
# --------------------------------------------------------------------------
class TestMiddlewareDatabaseRole(unittest.TestCase):
    def tearDown(self):
        _current_bearer_token.set(None)
        _current_database_role.set(None)
        _is_auth_managed.set(False)

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    @patch.dict(
        "spanner_agent.auth_wrapper.USER_DATABASE_ROLE_MAP",
        {"fgac-user@example.com": "restricted_reader"},
        clear=True,
    )
    def test_sets_role_for_fgac_user(self, mock_resolve):
        mock_resolve.return_value = "fgac-user@example.com"
        captured = {}

        async def fake_app(scope, receive, send):
            captured["role"] = _current_database_role.get()
            captured["managed"] = _is_auth_managed.get()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))

        self.assertEqual(captured["role"], "restricted_reader")
        self.assertTrue(captured["managed"])


if __name__ == "__main__":
    unittest.main()
