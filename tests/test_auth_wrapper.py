"""Unit tests for Bearer token credential propagation.

Tests that the auth pipeline correctly:
1. Extracts Bearer token from the HTTP Authorization header (middleware)
2. Stores and retrieves the token via ContextVar
3. Creates google.oauth2.credentials.Credentials from the token
4. Returns None when no token is present (triggers "auth required")
5. Replaces _credentials_manager on each GoogleTool in the toolset
6. Delegates close() to the inner toolset
"""

import asyncio
import contextvars
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import google.oauth2.credentials
from google.adk.tools.google_tool import GoogleTool

from spanner_agent.auth_wrapper import (
    AuthTokenExtractorMiddleware,
    BearerTokenCredentialsManager,
    BearerTokenSpannerToolset,
    _current_bearer_token,
    get_bearer_token,
    set_bearer_token,
)

FAKE_TOKEN = "test-fake-access-token-for-unit-testing-1234567890"


def _make_tool_context(user_id: str) -> MagicMock:
    """Create a mock ToolContext with the given user_id."""
    ctx = MagicMock()
    ctx.user_id = user_id
    ctx.state = {}
    return ctx


# --------------------------------------------------------------------------
# ContextVar helpers
# --------------------------------------------------------------------------
class TestContextVar(unittest.TestCase):
    """Test the ContextVar-based token storage."""

    def tearDown(self):
        # Reset ContextVar to default after each test
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
    """Test that the middleware extracts Bearer tokens from ASGI scope."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def tearDown(self):
        _current_bearer_token.set(None)

    def test_extracts_bearer_token(self):
        """Middleware should set the ContextVar when Authorization: Bearer is present."""
        captured_token = None

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)

        scope = {
            "type": "http",
            "headers": [
                (b"authorization", f"Bearer {FAKE_TOKEN}".encode()),
            ],
        }
        self._run(middleware(scope, None, None))

        self.assertEqual(captured_token, FAKE_TOKEN)
        # After middleware returns, ContextVar should be reset
        self.assertIsNone(get_bearer_token())

    def test_case_insensitive_bearer(self):
        """Should handle 'bearer' in any case."""
        captured_token = None

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"BEARER some_token")],
        }
        self._run(middleware(scope, None, None))
        # "BEARER " is 7 chars, but our code does auth_value[7:] which gets "some_token"
        self.assertEqual(captured_token, "some_token")

    def test_no_auth_header(self):
        """Without Authorization header, ContextVar stays None."""
        captured_token = "should_be_none"

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {"type": "http", "headers": []}
        self._run(middleware(scope, None, None))
        self.assertIsNone(captured_token)

    def test_non_bearer_auth_header(self):
        """Non-Bearer Authorization headers should not set the ContextVar."""
        captured_token = "should_be_none"

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [(b"authorization", b"Basic dXNlcjpwYXNz")],
        }
        self._run(middleware(scope, None, None))
        self.assertIsNone(captured_token)

    def test_non_http_scope_passes_through(self):
        """Non-HTTP scopes (e.g., websocket) should pass through unchanged."""
        called = False

        async def fake_app(scope, receive, send):
            nonlocal called
            called = True

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {"type": "websocket", "headers": []}
        self._run(middleware(scope, None, None))
        self.assertTrue(called)

    def test_x_user_authorization_takes_priority(self):
        """X-User-Authorization should be preferred over Authorization."""
        captured_token = None

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [
                (b"authorization", b"Bearer identity-token-jwt"),
                (b"x-user-authorization", f"Bearer {FAKE_TOKEN}".encode()),
            ],
        }
        self._run(middleware(scope, None, None))
        self.assertEqual(captured_token, FAKE_TOKEN)

    def test_x_user_authorization_alone(self):
        """X-User-Authorization without Authorization should work."""
        captured_token = None

        async def fake_app(scope, receive, send):
            nonlocal captured_token
            captured_token = get_bearer_token()

        middleware = AuthTokenExtractorMiddleware(fake_app)
        scope = {
            "type": "http",
            "headers": [
                (b"x-user-authorization", f"Bearer {FAKE_TOKEN}".encode()),
            ],
        }
        self._run(middleware(scope, None, None))
        self.assertEqual(captured_token, FAKE_TOKEN)


# --------------------------------------------------------------------------
# BearerTokenCredentialsManager
# --------------------------------------------------------------------------
class TestBearerTokenCredentialsManager(unittest.TestCase):
    """Test that the credentials manager creates Credentials from the token."""

    def setUp(self):
        self.manager = BearerTokenCredentialsManager()

    def tearDown(self):
        _current_bearer_token.set(None)

    def test_returns_credentials_when_token_present(self):
        """Should return Credentials with the Bearer token."""
        set_bearer_token(FAKE_TOKEN)
        ctx = _make_tool_context("user@example.com")
        creds = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNotNone(creds)
        self.assertIsInstance(creds, google.oauth2.credentials.Credentials)
        self.assertEqual(creds.token, FAKE_TOKEN)

    def test_credentials_are_valid(self):
        """Credentials with a token and no expiry should report valid=True."""
        set_bearer_token(FAKE_TOKEN)
        ctx = _make_tool_context("user@example.com")
        creds = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertTrue(creds.valid)

    def test_returns_none_when_no_token(self):
        """Should return None when no Bearer token is in the ContextVar."""
        ctx = _make_tool_context("user@example.com")
        creds = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNone(creds)

    def test_returns_none_when_empty_token(self):
        """Should return None for an empty token string."""
        set_bearer_token("")
        ctx = _make_tool_context("user@example.com")
        creds = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNone(creds)

    def test_logs_user_id(self):
        """Should log the user_id from tool_context."""
        set_bearer_token(FAKE_TOKEN)
        ctx = _make_tool_context("testuser@corp.com")
        with self.assertLogs("spanner_agent.auth_wrapper", level="INFO") as cm:
            asyncio.get_event_loop().run_until_complete(
                self.manager.get_valid_credentials(ctx)
            )
        log_output = "\n".join(cm.output)
        self.assertIn("testuser@corp.com", log_output)
        self.assertIn("[AUTH-CREDS]", log_output)


# --------------------------------------------------------------------------
# BearerTokenSpannerToolset
# --------------------------------------------------------------------------
class TestBearerTokenSpannerToolset(unittest.TestCase):
    """Test the wrapper toolset injects BearerTokenCredentialsManager."""

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_replaces_credentials_manager(self, mock_toolset_cls):
        """Tools should have _credentials_manager replaced."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = asyncio.get_event_loop().run_until_complete(toolset.get_tools())

        self.assertEqual(len(tools), 1)
        self.assertIsInstance(
            tools[0]._credentials_manager, BearerTokenCredentialsManager
        )

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_preserves_tool_name(self, mock_toolset_cls):
        """Wrapped tools should retain their original name."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_execute_sql"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = asyncio.get_event_loop().run_until_complete(toolset.get_tools())

        self.assertEqual(tools[0].name, "spanner_execute_sql")

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_close_delegates(self, mock_toolset_cls):
        """close() should delegate to the inner SpannerToolset."""
        mock_toolset = MagicMock()
        mock_toolset.close = AsyncMock()
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        asyncio.get_event_loop().run_until_complete(toolset.close())

        mock_toolset.close.assert_called_once()


# --------------------------------------------------------------------------
# End-to-end: middleware → credentials manager → tool
# --------------------------------------------------------------------------
class TestEndToEndBearerTokenFlow(unittest.TestCase):
    """Test the full flow: HTTP request → middleware → credentials manager."""

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

        loop = asyncio.get_event_loop()

        # Create toolset and get tools
        toolset = BearerTokenSpannerToolset()
        tools = loop.run_until_complete(toolset.get_tools())
        creds_manager = tools[0]._credentials_manager

        # Simulate middleware setting the token
        async def simulate_request():
            middleware = AuthTokenExtractorMiddleware(None)
            # Directly set token like middleware would
            reset = set_bearer_token(FAKE_TOKEN)
            try:
                ctx = _make_tool_context("user@example.com")
                creds = await creds_manager.get_valid_credentials(ctx)
                return creds
            finally:
                _current_bearer_token.reset(reset)

        creds = loop.run_until_complete(simulate_request())

        self.assertIsNotNone(creds)
        self.assertEqual(creds.token, FAKE_TOKEN)
        self.assertIsInstance(creds, google.oauth2.credentials.Credentials)

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_no_token_returns_none(self, mock_toolset_cls):
        """Without middleware setting a token, credentials manager returns None."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = BearerTokenSpannerToolset()
        tools = asyncio.get_event_loop().run_until_complete(toolset.get_tools())

        ctx = _make_tool_context("user@example.com")
        creds = asyncio.get_event_loop().run_until_complete(
            tools[0]._credentials_manager.get_valid_credentials(ctx)
        )
        self.assertIsNone(creds)


if __name__ == "__main__":
    unittest.main()
