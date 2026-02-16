"""Bearer token credential propagation for SpannerToolset (Cloud Run / A2A).

The end-user's OAuth access token arrives in HTTP headers when Gemini
Enterprise invokes the agent via A2A on Cloud Run.

Components:

1.  **AuthTokenExtractorMiddleware** — ASGI middleware that extracts the
    Bearer token from ``X-User-Authorization`` (or ``Authorization``) and
    stores it in a ContextVar.

2.  **BearerTokenCredentialsManager** — drop-in replacement for ADK's
    ``GoogleCredentialsManager``; reads the token from the ContextVar.

3.  **BearerTokenSpannerToolset** — ``BaseToolset`` wrapper that creates an
    inner ``SpannerToolset`` and replaces ``_credentials_manager`` on every
    ``GoogleTool`` with ``BearerTokenCredentialsManager``.

4.  **FGAC database-role injection** — monkey-patches
    ``Instance.database()`` so that the Spanner ``database_role`` parameter
    is automatically set based on the user's email (resolved from the OAuth
    token via the Google tokeninfo / userinfo APIs).
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any, Dict, List, Optional, Union

import os

import google.auth
import google.cloud.spanner_v1.database
import google.cloud.spanner_v1.instance
import google.oauth2.credentials
import httpx
from google.cloud.spanner_admin_database_v1.types import DatabaseDialect
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset, ToolPredicate
from google.adk.tools.google_tool import GoogleTool
from google.adk.tools.spanner.settings import SpannerToolSettings
from google.adk.tools.spanner.spanner_toolset import SpannerToolset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers — parse ``key=value,key=value`` environment variables
# ---------------------------------------------------------------------------
def _parse_key_value_env(raw: str) -> Dict[str, str]:
    """Parse a ``key=value,key=value`` string into a dict.

    Whitespace around keys and values is stripped.  Entries without an
    ``=`` sign are silently skipped.
    """
    result: Dict[str, str] = {}
    if not raw:
        return result
    for entry in raw.split(","):
        if "=" not in entry:
            continue
        k, v = entry.split("=", 1)
        result[k.strip()] = v.strip()
    return result


# ---------------------------------------------------------------------------
# User → Spanner database role mapping (for FGAC)
# ---------------------------------------------------------------------------
# Maps user email (or SA email) to the Spanner database role they should
# assume.  Users not in this map connect without a database role, so standard
# IAM access applies.
#
# Configure via the ``USER_DATABASE_ROLE_MAP`` environment variable using
# ``email=role`` pairs separated by commas, e.g.:
#   USER_DATABASE_ROLE_MAP="user@example.com=reader,sa@project.iam.gserviceaccount.com=reader"
USER_DATABASE_ROLE_MAP: Dict[str, str] = _parse_key_value_env(
    os.environ.get("USER_DATABASE_ROLE_MAP", "")
)

# ---------------------------------------------------------------------------
# ContextVars — per-request state visible across the async call-chain
# ---------------------------------------------------------------------------
_current_bearer_token: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("bearer_token", default=None)
)
_current_database_role: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("database_role", default=None)
)


def _resolve_user_email(token: str) -> Optional[str]:
    """Resolve the user's email from an OAuth access token.

    Tries Google's ``tokeninfo`` endpoint first, then falls back to
    ``userinfo``.  Returns ``None`` if the email cannot be determined
    (e.g. the token lacks the ``email`` scope).
    """
    # 1. tokeninfo — works when the token includes the email scope
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"access_token": token},
            timeout=5.0,
        )
        if resp.status_code == 200:
            email = resp.json().get("email")
            if email:
                logger.info("[AUTH] Resolved email=%s via tokeninfo", email)
                return email
        elif resp.status_code != 400:
            logger.debug("[AUTH] tokeninfo returned status=%d", resp.status_code)
    except Exception as exc:
        logger.debug("[AUTH] tokeninfo call failed: %s", exc)

    # 2. userinfo — works when the token includes email or openid scope
    try:
        resp = httpx.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            email = resp.json().get("email")
            if email:
                logger.info("[AUTH] Resolved email=%s via userinfo", email)
                return email
    except Exception as exc:
        logger.debug("[AUTH] userinfo call failed: %s", exc)

    logger.warning("[AUTH] Could not resolve email from token")
    return None


# ---------------------------------------------------------------------------
# Monkey-patch Instance.database() to inject database_role from ContextVar
# ---------------------------------------------------------------------------
_Instance = google.cloud.spanner_v1.instance.Instance
_original_instance_database = _Instance.database


def _patched_instance_database(self, database_id, *args, **kwargs):
    """Wrapper that injects ``database_role`` and pre-sets database dialect.

    Injects the FGAC ``database_role`` from the ContextVar when set.

    Pre-sets ``database_dialect`` to ``GOOGLE_STANDARD_SQL`` via the
    constructor parameter.  Without this, the first access to
    ``Database.database_dialect`` triggers ``reload()`` → ``getDdl``,
    which requires ``spanner.databases.getDdl`` — a permission that
    FGAC database roles typically lack.
    """
    db_role = _current_database_role.get()
    if db_role and "database_role" not in kwargs:
        logger.info(
            "[AUTH] Injecting database_role=%r for database=%s",
            db_role,
            database_id,
        )
        kwargs["database_role"] = db_role
    if "database_dialect" not in kwargs:
        kwargs["database_dialect"] = DatabaseDialect.GOOGLE_STANDARD_SQL
        logger.info(
            "[AUTH] Pre-set database_dialect=GOOGLE_STANDARD_SQL for %s",
            database_id,
        )
    return _original_instance_database(self, database_id, *args, **kwargs)


_Instance.database = _patched_instance_database


# ---------------------------------------------------------------------------
# Monkey-patch Database.database_dialect to avoid getDdl on every access
# ---------------------------------------------------------------------------
# The upstream Spanner client's ``Database.database_dialect`` property calls
# ``self.reload()`` whenever ``_database_dialect`` is
# ``DATABASE_DIALECT_UNSPECIFIED``.  ``reload()`` triggers
# ``get_database_ddl()`` which requires ``spanner.databases.getDdl`` — a
# permission that user-scoped OAuth tokens and FGAC database roles typically
# lack.
#
# The ``Instance.database()`` patch above pre-sets the dialect via the
# constructor kwarg, but as a defence-in-depth measure we also patch the
# *property* itself so that even if a ``Database`` object is created through
# a path we don't control, the property never calls ``reload()``.
_Database = google.cloud.spanner_v1.database.Database


def _safe_database_dialect(self):
    """Return the database dialect without triggering ``reload()``."""
    if self._database_dialect == DatabaseDialect.DATABASE_DIALECT_UNSPECIFIED:
        return DatabaseDialect.GOOGLE_STANDARD_SQL
    return self._database_dialect


_Database.database_dialect = property(_safe_database_dialect)


# ---------------------------------------------------------------------------
# Monkey-patch Database.reload() and Database.exists() to skip getDdl
# ---------------------------------------------------------------------------
# ``Database.reload()`` and ``Database.exists()`` both call
# ``api.get_database_ddl()`` which requires ``spanner.databases.getDdl``.
# User-scoped OAuth credentials and FGAC roles typically lack this.
#
# ``reload()`` is patched to only call ``get_database`` (requires the much
# less privileged ``spanner.databases.get``), skipping ``get_database_ddl``.
#
# ``exists()`` is patched to use ``get_database`` instead of
# ``get_database_ddl`` — same semantics (returns False on NotFound).
from google.api_core.exceptions import NotFound as _NotFound


def _safe_reload(self):
    """Reload database metadata without calling ``get_database_ddl()``.

    The upstream ``reload()`` calls both ``get_database_ddl()`` and
    ``get_database()``.  We skip the DDL call since it requires
    ``spanner.databases.getDdl`` which user-scoped credentials lack.
    """
    from google.cloud.spanner_v1.database import _metadata_with_prefix
    from google.cloud.spanner_admin_database_v1.types import (
        Database as DatabasePB,
    )

    api = self._instance._client.database_admin_api
    metadata = _metadata_with_prefix(self.name)
    response = api.get_database(
        name=self.name,
        metadata=self.metadata_with_request_id(
            self._next_nth_request, 1, metadata
        ),
    )
    self._state = DatabasePB.State(response.state)
    self._create_time = response.create_time
    self._restore_info = response.restore_info
    self._version_retention_period = response.version_retention_period
    self._earliest_version_time = response.earliest_version_time
    self._encryption_config = response.encryption_config
    self._encryption_info = response.encryption_info
    self._default_leader = response.default_leader
    if response.database_dialect != DatabaseDialect.DATABASE_DIALECT_UNSPECIFIED:
        self._database_dialect = response.database_dialect
    self._enable_drop_protection = response.enable_drop_protection
    self._reconciling = response.reconciling


_original_reload = _Database.reload
_Database.reload = _safe_reload


def _safe_exists(self):
    """Check database existence without calling ``get_database_ddl()``.

    Uses ``get_database`` (requires ``spanner.databases.get``) instead
    of ``get_database_ddl`` (requires ``spanner.databases.getDdl``).
    """
    from google.cloud.spanner_v1.database import _metadata_with_prefix

    api = self._instance._client.database_admin_api
    metadata = _metadata_with_prefix(self.name)
    try:
        api.get_database(
            name=self.name,
            metadata=self.metadata_with_request_id(
                self._next_nth_request, 1, metadata
            ),
        )
    except _NotFound:
        return False
    return True


_original_exists = _Database.exists
_Database.exists = _safe_exists


# ---------------------------------------------------------------------------
# Nuclear option: patch DatabaseAdminClient.get_database_ddl at the API level
# ---------------------------------------------------------------------------
# As a final defense-in-depth measure, patch the ``get_database_ddl`` method
# on ``DatabaseAdminClient`` itself.  If *any* code path — including ones in
# newer Spanner library versions that we haven't seen — attempts to call this
# API, it will receive an empty DDL response instead of hitting the Spanner
# admin API (which requires ``spanner.databases.getDdl``).
#
# This is intentionally the *last* patch so that the higher-level patches
# (property, reload, exists) prevent most callers from ever reaching here,
# and this layer catches anything that slips through.
from google.cloud.spanner_admin_database_v1.services.database_admin import (
    DatabaseAdminClient as _DatabaseAdminClient,
)
from google.cloud.spanner_admin_database_v1.types import (
    GetDatabaseDdlResponse as _GetDatabaseDdlResponse,
)

_original_get_database_ddl = _DatabaseAdminClient.get_database_ddl


def _blocked_get_database_ddl(self, *args, **kwargs):
    """Return an empty DDL response instead of calling the API.

    This prevents ``spanner.databases.getDdl`` permission errors for
    user-scoped OAuth credentials and FGAC database roles.
    """
    logger.info(
        "[AUTH] Blocked get_database_ddl call (would require getDdl permission)"
    )
    return _GetDatabaseDdlResponse(statements=[])


_DatabaseAdminClient.get_database_ddl = _blocked_get_database_ddl


# ---------------------------------------------------------------------------
# Project number → project ID normalization (before_tool_callback)
# ---------------------------------------------------------------------------
# The Spanner Python client fails with ``spanner.sessions.create`` permission
# denied when called with a project NUMBER (e.g. ``123456789``) and
# user-scoped OAuth2 credentials.  The LLM sometimes sends the project number
# instead of the project ID string.  This callback normalizes the
# ``project_id`` argument before the tool executes.
# Map of known project numbers → project ID strings.
# Configure via the ``PROJECT_NUMBER_MAP`` environment variable using
# ``number=id`` pairs separated by commas, e.g.:
#   PROJECT_NUMBER_MAP="123456789=my-project,987654321=other-project"
_PROJECT_NUMBER_TO_ID: Dict[str, str] = _parse_key_value_env(
    os.environ.get("PROJECT_NUMBER_MAP", "")
)


def _resolve_project_id(raw: str) -> str:
    """Resolve a project identifier to a string project ID.

    Returns the input unchanged if it's already a string project ID.
    """
    if raw and raw.isdigit():
        resolved = _PROJECT_NUMBER_TO_ID.get(raw)
        if resolved:
            return resolved
    return raw


_PROJECT_ID = _resolve_project_id(os.environ.get("GOOGLE_CLOUD_PROJECT", ""))


def normalize_project_id_callback(
    tool: Any, args: dict, tool_context: Any
) -> Optional[dict]:
    """Normalize numeric project IDs in Spanner tool arguments.

    Used as ``before_tool_callback`` on the Agent.  Modifies ``args`` in
    place and returns ``None`` so the tool executes normally.
    """
    project_id = args.get("project_id")
    if isinstance(project_id, str) and project_id.isdigit():
        resolved = _resolve_project_id(project_id)
        if resolved != project_id:
            logger.info(
                "[AUTH] Normalizing project_id %s → %s in tool %s",
                project_id,
                resolved,
                getattr(tool, "name", tool),
            )
            args["project_id"] = resolved
    return None


def get_bearer_token() -> Optional[str]:
    """Return the Bearer token for the current async context, or ``None``."""
    return _current_bearer_token.get()


def set_bearer_token(token: Optional[str]) -> contextvars.Token:
    """Set the Bearer token for the current async context."""
    return _current_bearer_token.set(token)


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------
class AuthTokenExtractorMiddleware:
    """ASGI middleware that extracts the end-user's Bearer token.

    Checks ``X-User-Authorization`` first (Cloud Run), then falls back to
    ``Authorization``.  Stores the token in a ContextVar so downstream code
    can retrieve it via :func:`get_bearer_token`.

    Also resolves the user's email from the token and sets the FGAC
    ``database_role`` ContextVar when the email appears in
    :data:`USER_DATABASE_ROLE_MAP`.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    @staticmethod
    def _extract_bearer(headers: dict[bytes, bytes]) -> tuple[str | None, str]:
        """Return ``(token, source_header)`` or ``(None, "")``."""
        for header, name in [
            (b"x-user-authorization", "X-User-Authorization"),
            (b"authorization", "Authorization"),
        ]:
            value = headers.get(header, b"").decode()
            if value.lower().startswith("bearer "):
                return value[7:], name
        return None, ""

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        token, source = self._extract_bearer(headers)

        if not token:
            await self.app(scope, receive, send)
            return

        logger.info("[AUTH] Bearer token from %s (length=%d)", source, len(token))
        reset_token = set_bearer_token(token)

        # Resolve user email → FGAC database role
        db_role = None
        email = _resolve_user_email(token)
        if email:
            db_role = USER_DATABASE_ROLE_MAP.get(email)
            if db_role:
                logger.info("[AUTH] %s → database_role=%s", email, db_role)
        reset_role = _current_database_role.set(db_role)

        try:
            await self.app(scope, receive, send)
        finally:
            _current_bearer_token.reset(reset_token)
            _current_database_role.reset(reset_role)


# ---------------------------------------------------------------------------
# Credentials manager (duck-types GoogleCredentialsManager)
# ---------------------------------------------------------------------------
class BearerTokenCredentialsManager:
    """Returns ``google.oauth2.credentials.Credentials`` from the Bearer token.

    Reads the token from the ContextVar ``_current_bearer_token`` which is
    set by ``AuthTokenExtractorMiddleware`` on each incoming HTTP request.

    If no token is found, returns ``None`` — which causes
    ``GoogleTool.run_async`` to return an "authorization required" message.
    """

    async def get_valid_credentials(
        self, tool_context: Any
    ) -> Optional[google.oauth2.credentials.Credentials]:
        token = get_bearer_token()

        if not token:
            logger.warning("[AUTH] No Bearer token available for Spanner call")
            return None

        return google.oauth2.credentials.Credentials(token=token)


# ---------------------------------------------------------------------------
# Toolset wrapper
# ---------------------------------------------------------------------------
class BearerTokenSpannerToolset(BaseToolset):
    """Wraps ``SpannerToolset`` so every ``GoogleTool`` uses the Bearer token.

    Replaces ``_credentials_manager`` on each tool with a
    :class:`BearerTokenCredentialsManager` that reads the per-request token
    from the ContextVar.
    """

    def __init__(
        self,
        *,
        tool_filter: Optional[Union[ToolPredicate, List[str]]] = None,
        spanner_tool_settings: Optional[SpannerToolSettings] = None,
    ) -> None:
        super().__init__(tool_filter=tool_filter)
        self._creds_manager = BearerTokenCredentialsManager()

        # SpannerCredentialsConfig requires *either* credentials or
        # client_id+client_secret.  We pass ADC to satisfy validation;
        # the credentials are never used because _credentials_manager is
        # replaced on every tool.
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
        """Get tools from the inner toolset with credentials replaced."""
        tools = await self._inner_toolset.get_tools(readonly_context)
        for tool in tools:
            if isinstance(tool, GoogleTool):
                tool._credentials_manager = self._creds_manager
        logger.info(
            "[AUTH] Prepared %d tool(s): %s",
            len(tools),
            [t.name for t in tools],
        )
        return tools

    async def close(self) -> None:
        """Delegate to the inner toolset."""
        await self._inner_toolset.close()
