"""Per-user SA impersonation wrapper for SpannerToolset.

Replaces the OAuth-based GoogleCredentialsManager on each GoogleTool with
an ImpersonatingCredentialsManager that maps tool_context.user_id to a
service account, then creates google.auth.impersonated_credentials.Credentials.

This avoids the unusable OAuth consent flow that occurs when SpannerToolset
is accessed through Gemini Enterprise via A2A.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

import google.auth
import google.auth.impersonated_credentials
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset, ToolPredicate
from google.adk.tools.google_tool import GoogleTool
from google.adk.tools.spanner.settings import SpannerToolSettings
from google.adk.tools.spanner.spanner_toolset import SpannerToolset

logger = logging.getLogger(__name__)

CLOUD_PLATFORM_SCOPE = ["https://www.googleapis.com/auth/cloud-platform"]

USER_SA_MAP: Dict[str, Dict[str, Any]] = {
    "adk-auth-exp-1@switon.altostrat.com": {
        "sa": "user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
        "database_role": None,
    },
    "adk-auth-exp-2@switon.altostrat.com": {
        "sa": "user2-no-access@switon-gsd-demos.iam.gserviceaccount.com",
        "database_role": None,
    },
    "adk-auth-exp-3@switon.altostrat.com": {
        "sa": "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com",
        "database_role": "employees_reader",
    },
}


class ImpersonatingCredentialsManager:
    """Duck-types GoogleCredentialsManager to return impersonated credentials.

    Maps tool_context.user_id to a service account via user_sa_map, then
    creates google.auth.impersonated_credentials.Credentials using the
    Cloud Run service account (ADC) as the source.

    Returns None for unknown users, which causes GoogleTool.run_async to
    return an "authorization required" message.
    """

    def __init__(self, user_sa_map: Dict[str, Dict[str, Any]]) -> None:
        self._user_sa_map = user_sa_map
        self._source_credentials: Optional[google.auth.credentials.Credentials] = None

    def _get_source_credentials(self) -> google.auth.credentials.Credentials:
        """Get and cache ADC source credentials."""
        if self._source_credentials is None:
            creds, _ = google.auth.default()
            self._source_credentials = creds
        return self._source_credentials

    async def get_valid_credentials(
        self, tool_context: Any
    ) -> Optional[google.auth.credentials.Credentials]:
        """Return impersonated credentials for the user, or None if unmapped."""
        user_id = getattr(tool_context, "user_id", None)
        if not user_id:
            logger.warning("No user_id in tool_context, returning None")
            return None

        mapping = self._user_sa_map.get(user_id)
        if mapping is None:
            logger.warning(
                "Unknown user_id %r not in user_sa_map, returning None", user_id
            )
            return None

        target_sa = mapping["sa"]
        source_creds = self._get_source_credentials()

        impersonated = google.auth.impersonated_credentials.Credentials(
            source_credentials=source_creds,
            target_principal=target_sa,
            target_scopes=CLOUD_PLATFORM_SCOPE,
        )

        logger.info(
            "Created impersonated credentials for user %s -> SA %s",
            user_id,
            target_sa,
        )
        return impersonated


class ImpersonatingSpannerToolset(BaseToolset):
    """Wraps SpannerToolset to inject per-user impersonated credentials.

    Creates an inner SpannerToolset, then replaces _credentials_manager on
    each GoogleTool with an ImpersonatingCredentialsManager.
    """

    def __init__(
        self,
        *,
        user_sa_map: Dict[str, Dict[str, Any]],
        tool_filter: Optional[Union[ToolPredicate, List[str]]] = None,
        spanner_tool_settings: Optional[SpannerToolSettings] = None,
    ) -> None:
        super().__init__(tool_filter=tool_filter)
        self._user_sa_map = user_sa_map
        self._creds_manager = ImpersonatingCredentialsManager(user_sa_map)

        # Pass ADC credentials to satisfy SpannerCredentialsConfig validation
        # (requires either credentials or client_id/client_secret).
        # These will be replaced by our ImpersonatingCredentialsManager.
        from google.adk.tools.spanner.spanner_credentials import (
            SpannerCredentialsConfig,
        )

        adc_creds, _ = google.auth.default()
        self._inner_toolset = SpannerToolset(
            credentials_config=SpannerCredentialsConfig(credentials=adc_creds),
            spanner_tool_settings=spanner_tool_settings,
            tool_filter=tool_filter,
        )

    async def get_tools(
        self, readonly_context: Optional[ReadonlyContext] = None
    ) -> List[BaseTool]:
        """Get tools from inner toolset with credentials manager replaced."""
        tools = await self._inner_toolset.get_tools(readonly_context)
        for tool in tools:
            if isinstance(tool, GoogleTool):
                tool._credentials_manager = self._creds_manager
        return tools

    async def close(self) -> None:
        """Delegate to inner toolset."""
        await self._inner_toolset.close()
