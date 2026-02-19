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
from unittest.mock import AsyncMock, MagicMock, patch

import google.auth
import google.oauth2.credentials
from google.adk.tools.google_tool import GoogleTool
from google.cloud.spanner_admin_database_v1.types import DatabaseDialect

from spanner_agent.auth_wrapper import (
    AuthTokenExtractorMiddleware,
    BearerTokenCredentialsManager,
    BearerTokenSpannerToolset,
    _current_bearer_token,
    _current_database_role,
    _is_auth_managed,
    _original_exists,
    _original_get_database_ddl,
    _original_instance_database,
    _parse_key_value_env,
    _patched_exists,
    _patched_get_database_ddl,
    _patched_instance_database,
    get_bearer_token,
    normalize_project_id_callback,
    set_bearer_token,
)

import google.cloud.spanner_v1.database

FAKE_TOKEN = "test-fake-access-token-for-unit-testing-1234567890"


def _make_tool_context(user_id: str) -> MagicMock:
    ctx = MagicMock()
    ctx.user_id = user_id
    ctx.state = {}
    return ctx


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

    def test_no_auth_header(self):
        captured = {"token": "should_be_none"}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {"type": "http", "headers": []}
        _run(middleware(scope, None, None))
        self.assertIsNone(captured["token"])

    def test_non_bearer_auth_header(self):
        captured = {"token": "should_be_none"}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Basic dXNlcjpwYXNz")],
        }
        _run(middleware(scope, None, None))
        self.assertIsNone(captured["token"])

    def test_non_http_scope_passes_through(self):
        called = False

        async def fake_app(scope, receive, send):
            nonlocal called
            called = True

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {"type": "websocket", "headers": []}
        _run(middleware(scope, None, None))
        self.assertTrue(called)

    def test_x_user_authorization_takes_priority(self):
        captured = {}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [
                (b"authorization", b"Bearer identity-token-jwt"),
                (b"x-user-authorization", f"Bearer {FAKE_TOKEN}".encode()),
            ],
        }
        _run(middleware(scope, None, None))
        self.assertEqual(captured["token"], FAKE_TOKEN)

    def test_x_user_authorization_alone(self):
        captured = {}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [
                (b"x-user-authorization", f"Bearer {FAKE_TOKEN}".encode()),
            ],
        }
        _run(middleware(scope, None, None))
        self.assertEqual(captured["token"], FAKE_TOKEN)


# --------------------------------------------------------------------------
# BearerTokenCredentialsManager
# --------------------------------------------------------------------------
class TestBearerTokenCredentialsManager(unittest.TestCase):
    def setUp(self):
        self.manager = BearerTokenCredentialsManager()

    def tearDown(self):
        _current_bearer_token.set(None)

    def test_returns_credentials_when_token_present(self):
        set_bearer_token(FAKE_TOKEN)
        ctx = _make_tool_context("user@example.com")
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNotNone(creds)
        self.assertIsInstance(creds, google.oauth2.credentials.Credentials)
        self.assertEqual(creds.token, FAKE_TOKEN)

    def test_credentials_are_valid(self):
        set_bearer_token(FAKE_TOKEN)
        ctx = _make_tool_context("user@example.com")
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertTrue(creds.valid)

    def test_returns_none_when_no_token(self):
        ctx = _make_tool_context("user@example.com")
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)

    def test_returns_none_when_empty_token(self):
        set_bearer_token("")
        ctx = _make_tool_context("user@example.com")
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)


# --------------------------------------------------------------------------
# BearerTokenSpannerToolset
# --------------------------------------------------------------------------
class TestBearerTokenSpannerToolset(unittest.TestCase):
    def setUp(self):
        # ADC mock for SpannerToolset init
        creds = google.oauth2.credentials.Credentials("dummy_token")
        self.patcher = patch("google.auth.default", return_value=(creds, "project"))
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_replaces_credentials_manager(self, mock_toolset_cls):
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = _run(toolset.get_tools())

        self.assertEqual(len(tools), 1)
        self.assertIsInstance(
            tools[0]._credentials_manager, BearerTokenCredentialsManager
        )

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_preserves_tool_name(self, mock_toolset_cls):
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_execute_sql"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = _run(toolset.get_tools())
        self.assertEqual(tools[0].name, "spanner_execute_sql")

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_close_delegates(self, mock_toolset_cls):
        mock_toolset = MagicMock()
        mock_toolset.close = AsyncMock()
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        _run(toolset.close())
        mock_toolset.close.assert_called_once()


# --------------------------------------------------------------------------
# End-to-end: middleware → credentials manager → tool
# --------------------------------------------------------------------------
class TestEndToEndBearerTokenFlow(unittest.TestCase):
    def setUp(self):
        creds = google.oauth2.credentials.Credentials("dummy_token")
        self.patcher = patch("google.auth.default", return_value=(creds, "project"))
        self.patcher.start()

    def tearDown(self):
        _current_bearer_token.set(None)
        self.patcher.stop()

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_middleware_to_credentials_manager(self, mock_toolset_cls):
        """Bearer token from HTTP header reaches the credentials manager."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_execute_sql"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = _run(toolset.get_tools())
        creds_manager = tools[0]._credentials_manager

        async def simulate_request():
            reset = set_bearer_token(FAKE_TOKEN)
            try:
                ctx = _make_tool_context("user@example.com")
                return await creds_manager.get_valid_credentials(ctx)
            finally:
                _current_bearer_token.reset(reset)

        creds = _run(simulate_request())
        self.assertIsNotNone(creds)
        self.assertEqual(creds.token, FAKE_TOKEN)

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_no_token_returns_none(self, mock_toolset_cls):
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = _run(toolset.get_tools())

        ctx = _make_tool_context("user@example.com")
        creds = _run(tools[0]._credentials_manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)


# --------------------------------------------------------------------------
# FGAC: database_role ContextVar and Instance.database() patch
# --------------------------------------------------------------------------
class TestDatabaseRoleContextVar(unittest.TestCase):
    def tearDown(self):
        _current_database_role.set(None)

    def test_default_is_none(self):
        self.assertIsNone(_current_database_role.get())

    def test_set_and_get(self):
        _current_database_role.set("employees_reader")
        self.assertEqual(_current_database_role.get(), "employees_reader")


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

    def test_passes_dialect_kwarg(self):
        """Passes database_dialect=GOOGLE_STANDARD_SQL to original method."""
        _is_auth_managed.set(True)
        mock_db = MagicMock()
        mock_instance = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_instance_database",
            return_value=mock_db,
        ) as mock_orig:
            _patched_instance_database(mock_instance, "test-db")

        mock_orig.assert_called_once_with(
            mock_instance,
            "test-db",
            database_dialect=DatabaseDialect.GOOGLE_STANDARD_SQL,
        )

    def test_preserves_explicit_dialect(self):
        """If dialect is explicitly passed, don't override it."""
        _is_auth_managed.set(True)
        mock_db = MagicMock()
        mock_instance = MagicMock()

        with patch(
            "spanner_agent.auth_wrapper._original_instance_database",
            return_value=mock_db,
        ) as mock_orig:
            _patched_instance_database(
                mock_instance,
                "test-db",
                database_dialect=DatabaseDialect.POSTGRESQL,
            )

        mock_orig.assert_called_once_with(
            mock_instance,
            "test-db",
            database_dialect=DatabaseDialect.POSTGRESQL,
        )


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
# Project ID normalization
# --------------------------------------------------------------------------
class TestNormalizeProjectIdCallback(unittest.TestCase):
    @patch.dict(
        "spanner_agent.auth_wrapper._PROJECT_NUMBER_TO_ID",
        {"111222333": "my-project"},
        clear=True,
    )
    def test_normalizes_numeric_project_id(self):
        tool = MagicMock()
        tool.name = "spanner_list_table_names"
        args = {"project_id": "111222333", "instance_id": "test-instance"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertEqual(args["project_id"], "my-project")

    def test_passes_string_project_id_unchanged(self):
        """Non-numeric project_id is passed through unchanged."""
        tool = MagicMock()
        tool.name = "spanner_execute_sql"
        args = {"project_id": "my-project", "instance_id": "test-instance"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertEqual(args["project_id"], "my-project")

    def test_no_project_id_args(self):
        """When project_id is not in args, callback does nothing."""
        tool = MagicMock()
        tool.name = "some_tool"
        args = {"query": "SELECT 1"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertNotIn("project_id", args)

    def test_non_string_project_id_unchanged(self):
        """Non-string project_id values are left unchanged."""
        tool = MagicMock()
        tool.name = "some_tool"
        args = {"project_id": 12345}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertEqual(args["project_id"], 12345)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class TestParseKeyValueEnv(unittest.TestCase):
    def test_parses_single_pair(self):
        result = _parse_key_value_env("111222333=my-project")
        self.assertEqual(result, {"111222333": "my-project"})

    def test_parses_multiple_pairs(self):
        result = _parse_key_value_env("111=proj-a,222=proj-b")
        self.assertEqual(result, {"111": "proj-a", "222": "proj-b"})

    def test_returns_empty_dict_for_empty_string(self):
        result = _parse_key_value_env("")
        self.assertEqual(result, {})

    def test_strips_whitespace(self):
        result = _parse_key_value_env(" 111 = proj-a , 222 = proj-b ")
        self.assertEqual(result, {"111": "proj-a", "222": "proj-b"})

    def test_skips_malformed_entries(self):
        result = _parse_key_value_env("111=proj-a,bad-entry,222=proj-b")
        self.assertEqual(result, {"111": "proj-a", "222": "proj-b"})


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

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_no_role_for_regular_user(self, mock_resolve):
        mock_resolve.return_value = "regular-user@example.com"
        captured = {"role": "should_be_none"}

        async def fake_app(scope, receive, send):
            captured["role"] = _current_database_role.get()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))
        self.assertIsNone(captured["role"])

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_no_role_when_email_resolution_fails(self, mock_resolve):
        mock_resolve.return_value = None
        captured = {"role": "should_be_none"}

        async def fake_app(scope, receive, send):
            captured["role"] = _current_database_role.get()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))
        self.assertIsNone(captured["role"])


if __name__ == "__main__":
    unittest.main()
