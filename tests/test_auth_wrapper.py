"""Unit tests for auth wrapper — user identity propagation and SA impersonation.

Tests that the ImpersonatingSpannerToolset correctly:
1. Extracts user_id from tool_context
2. Maps user email to the right service account
3. Creates impersonated credentials for the mapped SA
4. Passes impersonated credentials to underlying SpannerToolset tools
5. Returns clear error for unknown/unmapped users
6. Propagates database_role for FGAC users
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import google.auth.credentials
import google.auth.impersonated_credentials
from google.adk.tools.google_tool import GoogleTool

from spanner_agent.auth_wrapper import (
    USER_SA_MAP,
    ImpersonatingCredentialsManager,
    ImpersonatingSpannerToolset,
)

USER1_EMAIL = "adk-auth-exp-1@switon.altostrat.com"
USER2_EMAIL = "adk-auth-exp-2@switon.altostrat.com"
USER3_EMAIL = "adk-auth-exp-3@switon.altostrat.com"
UNKNOWN_USER = "A2A_USER_abc123"


def _make_tool_context(user_id: str) -> MagicMock:
    """Create a mock ToolContext with the given user_id."""
    ctx = MagicMock()
    ctx.user_id = user_id
    ctx.state = {}
    return ctx


class TestUserSAMapping(unittest.TestCase):
    """Test that USER_SA_MAP contains correct mappings."""

    def test_user1_mapped_to_full_access_sa(self):
        self.assertIn(USER1_EMAIL, USER_SA_MAP)
        self.assertEqual(
            USER_SA_MAP[USER1_EMAIL]["sa"],
            "user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
        )

    def test_user1_has_no_database_role(self):
        self.assertIsNone(USER_SA_MAP[USER1_EMAIL]["database_role"])

    def test_user2_mapped_to_no_access_sa(self):
        self.assertIn(USER2_EMAIL, USER_SA_MAP)
        self.assertEqual(
            USER_SA_MAP[USER2_EMAIL]["sa"],
            "user2-no-access@switon-gsd-demos.iam.gserviceaccount.com",
        )

    def test_user2_has_no_database_role(self):
        self.assertIsNone(USER_SA_MAP[USER2_EMAIL]["database_role"])

    def test_user3_mapped_to_fgac_sa(self):
        self.assertIn(USER3_EMAIL, USER_SA_MAP)
        self.assertEqual(
            USER_SA_MAP[USER3_EMAIL]["sa"],
            "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com",
        )

    def test_user3_has_employees_reader_role(self):
        self.assertEqual(
            USER_SA_MAP[USER3_EMAIL]["database_role"], "employees_reader"
        )


class TestImpersonatingCredentialsManager(unittest.TestCase):
    """Test credential manager creates correct impersonated credentials."""

    def setUp(self):
        self.manager = ImpersonatingCredentialsManager(USER_SA_MAP)

    @patch("spanner_agent.auth_wrapper.google.auth.default")
    @patch("spanner_agent.auth_wrapper.google.auth.impersonated_credentials.Credentials")
    def test_known_user_gets_impersonated_credentials(
        self, mock_impersonated_creds, mock_auth_default
    ):
        """A known user should get impersonated credentials for their SA."""
        mock_source_creds = MagicMock(spec=google.auth.credentials.Credentials)
        mock_auth_default.return_value = (mock_source_creds, "project-id")
        mock_impersonated = MagicMock()
        mock_impersonated_creds.return_value = mock_impersonated

        ctx = _make_tool_context(USER1_EMAIL)
        result = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )

        self.assertEqual(result, mock_impersonated)
        mock_impersonated_creds.assert_called_once_with(
            source_credentials=mock_source_creds,
            target_principal="user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    @patch("spanner_agent.auth_wrapper.google.auth.default")
    @patch("spanner_agent.auth_wrapper.google.auth.impersonated_credentials.Credentials")
    def test_user2_gets_their_sa_credentials(
        self, mock_impersonated_creds, mock_auth_default
    ):
        """User 2 should get credentials for user2-no-access SA."""
        mock_source_creds = MagicMock(spec=google.auth.credentials.Credentials)
        mock_auth_default.return_value = (mock_source_creds, "project-id")
        mock_impersonated = MagicMock()
        mock_impersonated_creds.return_value = mock_impersonated

        ctx = _make_tool_context(USER2_EMAIL)
        result = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )

        mock_impersonated_creds.assert_called_once_with(
            source_credentials=mock_source_creds,
            target_principal="user2-no-access@switon-gsd-demos.iam.gserviceaccount.com",
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    @patch("spanner_agent.auth_wrapper.google.auth.default")
    @patch("spanner_agent.auth_wrapper.google.auth.impersonated_credentials.Credentials")
    def test_user3_gets_their_sa_credentials(
        self, mock_impersonated_creds, mock_auth_default
    ):
        """User 3 should get credentials for user3-fgac SA."""
        mock_source_creds = MagicMock(spec=google.auth.credentials.Credentials)
        mock_auth_default.return_value = (mock_source_creds, "project-id")
        mock_impersonated = MagicMock()
        mock_impersonated_creds.return_value = mock_impersonated

        ctx = _make_tool_context(USER3_EMAIL)
        result = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )

        mock_impersonated_creds.assert_called_once_with(
            source_credentials=mock_source_creds,
            target_principal="user3-fgac@switon-gsd-demos.iam.gserviceaccount.com",
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    def test_unknown_user_returns_none(self):
        """An unknown user should get None (triggers auth required message)."""
        ctx = _make_tool_context(UNKNOWN_USER)
        result = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNone(result)

    def test_empty_user_id_returns_none(self):
        """Empty user_id should return None."""
        ctx = _make_tool_context("")
        result = asyncio.get_event_loop().run_until_complete(
            self.manager.get_valid_credentials(ctx)
        )
        self.assertIsNone(result)

    @patch("spanner_agent.auth_wrapper.google.auth.default")
    @patch("spanner_agent.auth_wrapper.google.auth.impersonated_credentials.Credentials")
    def test_source_credentials_cached(
        self, mock_impersonated_creds, mock_auth_default
    ):
        """Source credentials should be fetched once and reused."""
        mock_source_creds = MagicMock(spec=google.auth.credentials.Credentials)
        mock_auth_default.return_value = (mock_source_creds, "project-id")
        mock_impersonated_creds.return_value = MagicMock()

        ctx1 = _make_tool_context(USER1_EMAIL)
        ctx2 = _make_tool_context(USER2_EMAIL)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.manager.get_valid_credentials(ctx1))
        loop.run_until_complete(self.manager.get_valid_credentials(ctx2))

        # google.auth.default() should only be called once
        mock_auth_default.assert_called_once()


class TestImpersonatingSpannerToolset(unittest.TestCase):
    """Test the wrapper toolset injects credentials manager into tools."""

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_replaces_credentials_manager(self, mock_toolset_cls):
        """Tools returned should have their credentials_manager replaced."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = ImpersonatingSpannerToolset(user_sa_map=USER_SA_MAP)
        loop = asyncio.get_event_loop()
        tools = loop.run_until_complete(toolset.get_tools())

        self.assertEqual(len(tools), 1)
        # The tool's credentials manager should be an ImpersonatingCredentialsManager
        self.assertIsInstance(
            tools[0]._credentials_manager, ImpersonatingCredentialsManager
        )

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_get_tools_preserves_tool_functionality(self, mock_toolset_cls):
        """Wrapped tools should retain their name and other attributes."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_execute_sql"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = ImpersonatingSpannerToolset(user_sa_map=USER_SA_MAP)
        loop = asyncio.get_event_loop()
        tools = loop.run_until_complete(toolset.get_tools())

        self.assertEqual(tools[0].name, "spanner_execute_sql")

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_close_delegates_to_inner_toolset(self, mock_toolset_cls):
        """close() should delegate to the inner SpannerToolset."""
        mock_toolset = MagicMock()
        mock_toolset.close = AsyncMock()
        mock_toolset_cls.return_value = mock_toolset

        toolset = ImpersonatingSpannerToolset(user_sa_map=USER_SA_MAP)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(toolset.close())

        mock_toolset.close.assert_called_once()


class TestEndToEndCredentialFlow(unittest.TestCase):
    """Test the full flow: user request → credential resolution → tool call."""

    @patch("spanner_agent.auth_wrapper.google.auth.default")
    @patch("spanner_agent.auth_wrapper.google.auth.impersonated_credentials.Credentials")
    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_tool_receives_impersonated_credentials_for_known_user(
        self, mock_toolset_cls, mock_impersonated_creds, mock_auth_default
    ):
        """When a known user calls a tool, it should receive impersonated credentials."""
        # Set up source credentials
        mock_source_creds = MagicMock(spec=google.auth.credentials.Credentials)
        mock_auth_default.return_value = (mock_source_creds, "project-id")

        # Set up impersonated credentials
        mock_impersonated = MagicMock()
        mock_impersonated_creds.return_value = mock_impersonated

        # Set up mock tool with a real-ish credentials_manager
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_execute_sql"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        # Create toolset and get tools
        toolset = ImpersonatingSpannerToolset(user_sa_map=USER_SA_MAP)
        loop = asyncio.get_event_loop()
        tools = loop.run_until_complete(toolset.get_tools())

        # Simulate the credentials manager being called with a user context
        ctx = _make_tool_context(USER1_EMAIL)
        creds_manager = tools[0]._credentials_manager
        creds = loop.run_until_complete(creds_manager.get_valid_credentials(ctx))

        # Should return impersonated credentials
        self.assertEqual(creds, mock_impersonated)
        mock_impersonated_creds.assert_called_once_with(
            source_credentials=mock_source_creds,
            target_principal="user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    @patch("spanner_agent.auth_wrapper.SpannerToolset")
    def test_tool_returns_auth_required_for_unknown_user(
        self, mock_toolset_cls
    ):
        """When an unknown user calls a tool, credentials manager returns None."""
        mock_tool = MagicMock(spec=GoogleTool)
        mock_tool._credentials_manager = MagicMock()
        mock_tool.name = "spanner_list_table_names"

        mock_toolset = MagicMock()
        mock_toolset.get_tools = AsyncMock(return_value=[mock_tool])
        mock_toolset_cls.return_value = mock_toolset

        toolset = ImpersonatingSpannerToolset(user_sa_map=USER_SA_MAP)
        loop = asyncio.get_event_loop()
        tools = loop.run_until_complete(toolset.get_tools())

        ctx = _make_tool_context(UNKNOWN_USER)
        creds_manager = tools[0]._credentials_manager
        creds = loop.run_until_complete(creds_manager.get_valid_credentials(ctx))

        # Should return None, which makes GoogleTool return "authorization required"
        self.assertIsNone(creds)


if __name__ == "__main__":
    unittest.main()
