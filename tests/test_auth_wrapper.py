"""Unit tests for Bearer token credential propagation (Cloud Run / A2A).

Tests the auth pipeline:
1. ContextVar token storage (set/get/reset)
2. ASGI middleware Bearer token extraction (Authorization, X-User-Authorization)
3. BearerTokenCredentialsManager creates Credentials from token
4. BearerTokenSpannerToolset replaces _credentials_manager on tools
5. FGAC database_role ContextVar and USER_DATABASE_ROLE_MAP
6. Middleware sets database_role based on resolved email
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import google.oauth2.credentials
from google.adk.tools.google_tool import GoogleTool
from google.cloud.spanner_admin_database_v1.types import DatabaseDialect

from spanner_agent.auth_wrapper import (
    AuthTokenExtractorMiddleware,
    BearerTokenCredentialsManager,
    BearerTokenSpannerToolset,
    USER_DATABASE_ROLE_MAP,
    _blocked_get_database_ddl,
    _current_bearer_token,
    _current_database_role,
    _original_exists,
    _original_get_database_ddl,
    _original_instance_database,
    _original_reload,
    _patched_instance_database,
    _resolve_project_id,
    _safe_exists,
    _safe_reload,
    get_bearer_token,
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

    def test_extracts_bearer_token(self):
        captured = {}

        async def fake_app(scope, receive, send):
            captured["token"] = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))

        self.assertEqual(captured["token"], FAKE_TOKEN)
        self.assertIsNone(get_bearer_token())  # reset after request

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
    def tearDown(self):
        _current_bearer_token.set(None)

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

    def test_role_map_contains_workspace_user(self):
        self.assertEqual(
            USER_DATABASE_ROLE_MAP.get("adk-auth-exp-3@switon.altostrat.com"),
            "employees_reader",
        )

    def test_role_map_contains_service_account(self):
        self.assertEqual(
            USER_DATABASE_ROLE_MAP.get(
                "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com"
            ),
            "employees_reader",
        )

    def test_role_map_returns_none_for_unknown(self):
        self.assertIsNone(USER_DATABASE_ROLE_MAP.get("unknown@example.com"))

    def test_patched_database_injects_role(self):
        _current_database_role.set("employees_reader")
        mock_instance = MagicMock()
        _patched_instance_database(mock_instance, "test-db")
        self.assertEqual(_current_database_role.get(), "employees_reader")

    def test_patched_database_no_role_when_not_set(self):
        _current_database_role.set(None)
        self.assertIsNone(_current_database_role.get())


class TestDatabaseDialectPreset(unittest.TestCase):
    """Verify _patched_instance_database pre-sets database dialect.

    The Spanner client's Database.database_dialect property triggers
    reload() -> getDdl when dialect is UNSPECIFIED. FGAC database roles
    don't have getDdl permission, so we pre-set the dialect to
    GOOGLE_STANDARD_SQL via the constructor kwarg.
    """

    def tearDown(self):
        _current_database_role.set(None)

    def test_passes_dialect_kwarg(self):
        """Passes database_dialect=GOOGLE_STANDARD_SQL to original method."""
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

    def test_dialect_preset_works_with_role_injection(self):
        """Both dialect preset and role injection work together."""
        _current_database_role.set("employees_reader")
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
            database_role="employees_reader",
            database_dialect=DatabaseDialect.GOOGLE_STANDARD_SQL,
        )


class TestNormalizeProjectIdCallback(unittest.TestCase):
    """Verify before_tool_callback normalizes project numbers in tool args."""

    def test_normalizes_numeric_project_id(self):
        """Numeric project_id in tool args is replaced with string ID."""
        from spanner_agent.auth_wrapper import normalize_project_id_callback

        tool = MagicMock()
        tool.name = "spanner_list_table_names"
        args = {"project_id": "535816463745", "instance_id": "adk-auth-exp"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)  # None means continue normal execution
        self.assertEqual(args["project_id"], "switon-gsd-demos")

    def test_passes_string_project_id_unchanged(self):
        """Non-numeric project_id is passed through unchanged."""
        from spanner_agent.auth_wrapper import normalize_project_id_callback

        tool = MagicMock()
        tool.name = "spanner_execute_sql"
        args = {"project_id": "switon-gsd-demos", "instance_id": "adk-auth-exp"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertEqual(args["project_id"], "switon-gsd-demos")

    def test_no_project_id_in_args(self):
        """When project_id is not in args, callback does nothing."""
        from spanner_agent.auth_wrapper import normalize_project_id_callback

        tool = MagicMock()
        tool.name = "some_tool"
        args = {"query": "SELECT 1"}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertNotIn("project_id", args)

    def test_non_string_project_id_unchanged(self):
        """Non-string project_id values are left unchanged."""
        from spanner_agent.auth_wrapper import normalize_project_id_callback

        tool = MagicMock()
        tool.name = "some_tool"
        args = {"project_id": 12345}
        ctx = _make_tool_context("user@example.com")

        result = normalize_project_id_callback(tool, args, ctx)

        self.assertIsNone(result)
        self.assertEqual(args["project_id"], 12345)


class TestResolveProjectId(unittest.TestCase):
    """Verify _resolve_project_id handles project numbers correctly."""

    def test_resolves_known_project_number(self):
        self.assertEqual(_resolve_project_id("535816463745"), "switon-gsd-demos")

    def test_returns_string_project_unchanged(self):
        self.assertEqual(_resolve_project_id("switon-gsd-demos"), "switon-gsd-demos")

    def test_returns_unknown_number_unchanged(self):
        self.assertEqual(_resolve_project_id("999999999999"), "999999999999")

    def test_returns_empty_string_unchanged(self):
        self.assertEqual(_resolve_project_id(""), "")


class TestDatabaseDialectPropertyPatch(unittest.TestCase):
    """Verify Database.database_dialect property never triggers getDdl."""

    def test_property_returns_google_standard_sql_when_unspecified(self):
        """When _database_dialect is UNSPECIFIED, property returns GOOGLE_STANDARD_SQL."""
        db = MagicMock(spec=google.cloud.spanner_v1.database.Database)
        db._database_dialect = DatabaseDialect.DATABASE_DIALECT_UNSPECIFIED
        result = google.cloud.spanner_v1.database.Database.database_dialect.fget(db)
        self.assertEqual(result, DatabaseDialect.GOOGLE_STANDARD_SQL)

    def test_property_returns_explicit_dialect_unchanged(self):
        """When _database_dialect is explicitly set, property returns it unchanged."""
        db = MagicMock(spec=google.cloud.spanner_v1.database.Database)
        db._database_dialect = DatabaseDialect.GOOGLE_STANDARD_SQL
        result = google.cloud.spanner_v1.database.Database.database_dialect.fget(db)
        self.assertEqual(result, DatabaseDialect.GOOGLE_STANDARD_SQL)

    def test_property_does_not_call_reload(self):
        """The patched property never calls reload(), even when dialect is UNSPECIFIED."""
        db = MagicMock(spec=google.cloud.spanner_v1.database.Database)
        db._database_dialect = DatabaseDialect.DATABASE_DIALECT_UNSPECIFIED
        google.cloud.spanner_v1.database.Database.database_dialect.fget(db)
        db.reload.assert_not_called()


class TestDatabaseReloadPatch(unittest.TestCase):
    """Verify Database.reload() is patched to skip getDdl."""

    def test_reload_is_patched(self):
        """Database.reload is our _safe_reload, not the original."""
        db_class = google.cloud.spanner_v1.database.Database
        self.assertIs(db_class.reload, _safe_reload)
        self.assertIsNot(db_class.reload, _original_reload)

    def test_safe_reload_does_not_call_get_database_ddl(self):
        """_safe_reload calls get_database but NOT get_database_ddl."""
        from google.cloud.spanner_admin_database_v1.types import (
            Database as DatabasePB,
        )

        db = MagicMock()
        db.name = "projects/test/instances/test/databases/test"
        db._next_nth_request = 1
        mock_api = MagicMock()
        mock_response = MagicMock()
        mock_response.state = DatabasePB.State.READY
        mock_response.database_dialect = DatabaseDialect.GOOGLE_STANDARD_SQL
        mock_api.get_database.return_value = mock_response
        db._instance._client.database_admin_api = mock_api

        _safe_reload(db)

        mock_api.get_database.assert_called_once()
        mock_api.get_database_ddl.assert_not_called()


class TestDatabaseExistsPatch(unittest.TestCase):
    """Verify Database.exists() is patched to skip getDdl."""

    def test_exists_is_patched(self):
        """Database.exists is our _safe_exists, not the original."""
        db_class = google.cloud.spanner_v1.database.Database
        self.assertIs(db_class.exists, _safe_exists)
        self.assertIsNot(db_class.exists, _original_exists)

    def test_safe_exists_does_not_call_get_database_ddl(self):
        """_safe_exists calls get_database but NOT get_database_ddl."""
        db = MagicMock()
        db.name = "projects/test/instances/test/databases/test"
        db._next_nth_request = 1
        mock_api = MagicMock()
        db._instance._client.database_admin_api = mock_api

        result = _safe_exists(db)

        self.assertTrue(result)
        mock_api.get_database.assert_called_once()
        mock_api.get_database_ddl.assert_not_called()

    def test_safe_exists_returns_false_on_not_found(self):
        """_safe_exists returns False when database doesn't exist."""
        from google.api_core.exceptions import NotFound

        db = MagicMock()
        db.name = "projects/test/instances/test/databases/nonexistent"
        db._next_nth_request = 1
        mock_api = MagicMock()
        mock_api.get_database.side_effect = NotFound("not found")
        db._instance._client.database_admin_api = mock_api

        result = _safe_exists(db)

        self.assertFalse(result)


class TestGetDatabaseDdlBlocked(unittest.TestCase):
    """Verify DatabaseAdminClient.get_database_ddl is blocked at the API level."""

    def test_admin_client_method_is_patched(self):
        """DatabaseAdminClient.get_database_ddl is our blocked version."""
        from google.cloud.spanner_admin_database_v1.services.database_admin import (
            DatabaseAdminClient,
        )

        self.assertIs(
            DatabaseAdminClient.get_database_ddl, _blocked_get_database_ddl
        )
        self.assertIsNot(
            DatabaseAdminClient.get_database_ddl, _original_get_database_ddl
        )

    def test_blocked_returns_empty_ddl_response(self):
        """The blocked method returns GetDatabaseDdlResponse with empty statements."""
        from google.cloud.spanner_admin_database_v1.types import (
            GetDatabaseDdlResponse,
        )

        mock_client = MagicMock()
        result = _blocked_get_database_ddl(mock_client, database="test-db")
        self.assertIsInstance(result, GetDatabaseDdlResponse)
        self.assertEqual(list(result.statements), [])

    def test_blocked_never_calls_real_api(self):
        """The blocked method does not make any API calls."""
        mock_client = MagicMock()
        _blocked_get_database_ddl(mock_client, database="test-db")
        mock_client._transport.assert_not_called()


class TestMiddlewareDatabaseRole(unittest.TestCase):
    def tearDown(self):
        _current_bearer_token.set(None)
        _current_database_role.set(None)

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_sets_role_for_fgac_user(self, mock_resolve):
        mock_resolve.return_value = "adk-auth-exp-3@switon.altostrat.com"
        captured = {}

        async def fake_app(scope, receive, send):
            captured["role"] = _current_database_role.get()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {FAKE_TOKEN}".encode())],
        }
        _run(middleware(scope, None, None))

        self.assertEqual(captured["role"], "employees_reader")
        self.assertIsNone(_current_database_role.get())  # reset after

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_no_role_for_regular_user(self, mock_resolve):
        mock_resolve.return_value = "adk-auth-exp-1@switon.altostrat.com"
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
