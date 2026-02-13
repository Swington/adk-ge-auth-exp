"""Unit tests for Bearer token credential propagation.

Tests the auth pipeline:
1. ContextVar token storage (set/get/reset)
2. ASGI middleware Bearer token extraction (Authorization, X-User-Authorization)
3. BearerTokenCredentialsManager creates Credentials from token
4. BearerTokenSpannerToolset replaces _credentials_manager on tools
5. FGAC database_role ContextVar and USER_DATABASE_ROLE_MAP
6. Middleware sets database_role based on resolved email
7. Agent Engine path: token from tool_context.state + lazy FGAC resolution
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import google.oauth2.credentials
from google.adk.tools.google_tool import GoogleTool

from spanner_agent.auth_wrapper import (
    AuthTokenExtractorMiddleware,
    BearerTokenCredentialsManager,
    BearerTokenSpannerToolset,
    USER_DATABASE_ROLE_MAP,
    _current_bearer_token,
    _current_database_role,
    _original_instance_database,
    _patched_instance_database,
    get_bearer_token,
    set_bearer_token,
)

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


# --------------------------------------------------------------------------
# Agent Engine path: token from tool_context.state
# --------------------------------------------------------------------------
class TestCredentialsManagerFromState(unittest.TestCase):
    """BearerTokenCredentialsManager reads token from tool_context.state
    when ContextVar is empty (Agent Engine deployment path).
    """

    def setUp(self):
        self.manager = BearerTokenCredentialsManager()

    def tearDown(self):
        _current_bearer_token.set(None)
        _current_database_role.set(None)

    def test_reads_token_from_state(self):
        """When ContextVar is empty, reads token from tool_context.state."""
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"my_auth_resource": FAKE_TOKEN}
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNotNone(creds)
        self.assertEqual(creds.token, FAKE_TOKEN)

    def test_contextvar_takes_priority_over_state(self):
        """ContextVar (Cloud Run) takes priority over state (Agent Engine)."""
        set_bearer_token("contextvar-token")
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"my_auth_resource": "state-token"}
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertEqual(creds.token, "contextvar-token")

    def test_returns_none_when_state_empty(self):
        ctx = _make_tool_context("user@example.com")
        ctx.state = {}
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)

    def test_returns_none_when_no_tool_context(self):
        creds = _run(self.manager.get_valid_credentials(None))
        self.assertIsNone(creds)

    def test_skips_non_string_state_values(self):
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"counter": 42, "flag": True}
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)

    def test_skips_short_string_state_values(self):
        """Short strings are not access tokens."""
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"status": "ok", "mode": "read"}
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNone(creds)

    def test_reads_token_from_adk_state_object(self):
        """Works with ADK State objects that have to_dict() instead of values()."""
        ctx = _make_tool_context("user@example.com")
        # Simulate ADK State object (has to_dict but no values)
        mock_state = MagicMock()
        mock_state.__bool__ = MagicMock(return_value=True)
        mock_state.to_dict.return_value = {"auth_id_123": FAKE_TOKEN}
        del mock_state.values  # State doesn't have .values()
        ctx.state = mock_state
        creds = _run(self.manager.get_valid_credentials(ctx))
        self.assertIsNotNone(creds)
        self.assertEqual(creds.token, FAKE_TOKEN)

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_sets_fgac_role_from_state_token(self, mock_resolve):
        """Agent Engine path: resolves email and sets database_role.

        ContextVar changes inside an asyncio Task are isolated, so we
        capture the value inside the coroutine.
        """
        mock_resolve.return_value = "adk-auth-exp-3@switon.altostrat.com"
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"my_auth_resource": FAKE_TOKEN}

        async def run_and_capture():
            creds = await self.manager.get_valid_credentials(ctx)
            return creds, _current_database_role.get()

        creds, role = _run(run_and_capture())
        self.assertIsNotNone(creds)
        self.assertEqual(role, "employees_reader")

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_no_fgac_role_for_regular_user_from_state(self, mock_resolve):
        mock_resolve.return_value = "adk-auth-exp-1@switon.altostrat.com"
        ctx = _make_tool_context("user@example.com")
        ctx.state = {"my_auth_resource": FAKE_TOKEN}

        async def run_and_capture():
            await self.manager.get_valid_credentials(ctx)
            return _current_database_role.get()

        role = _run(run_and_capture())
        self.assertIsNone(role)

    @patch("spanner_agent.auth_wrapper._resolve_user_email")
    def test_skips_fgac_when_contextvar_already_set(self, mock_resolve):
        """Cloud Run path: middleware already set the role, don't re-resolve."""
        set_bearer_token(FAKE_TOKEN)
        _current_database_role.set("employees_reader")
        ctx = _make_tool_context("user@example.com")
        _run(self.manager.get_valid_credentials(ctx))
        mock_resolve.assert_not_called()


# --------------------------------------------------------------------------
# AdkApp monkey-patch for Agent Engine kwargs compatibility
# --------------------------------------------------------------------------
class TestAdkAppPatch(unittest.TestCase):
    def test_patched_method_exists(self):
        """The AdkApp monkey-patch was applied at import time."""
        from vertexai.agent_engines import AdkApp

        method = getattr(AdkApp, "streaming_agent_run_with_events", None)
        self.assertIsNotNone(method)
        # The patched method should accept **kwargs
        import inspect

        sig = inspect.signature(method)
        param_names = list(sig.parameters.keys())
        # Should have 'self', 'request_json', and '**kwargs'
        self.assertIn("request_json", param_names)
        self.assertIn("kwargs", param_names)


if __name__ == "__main__":
    unittest.main()
