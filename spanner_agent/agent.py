"""ADK Agent with Spanner Toolkit for auth propagation experiment."""

import logging
import os

from google.adk.agents import Agent
from google.adk.tools.spanner.settings import Capabilities, SpannerToolSettings

from .auth_wrapper import (
    BearerTokenSpannerToolset,
    _resolve_project_id,
    normalize_project_id_callback,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PROJECT_ID = _resolve_project_id(
    os.environ.get("GOOGLE_CLOUD_PROJECT", "switon-gsd-demos")
)
SPANNER_INSTANCE_ID = os.environ.get("SPANNER_INSTANCE_ID", "adk-auth-exp")
SPANNER_DATABASE_ID = os.environ.get("SPANNER_DATABASE_ID", "demo-db")

spanner_toolset = BearerTokenSpannerToolset(
    spanner_tool_settings=SpannerToolSettings(
        capabilities=[Capabilities.DATA_READ],
        max_executed_query_result_rows=100,
    ),
)

AGENT_INSTRUCTION = f"""You are a helpful data assistant that can query a Spanner database.

You have access to the following Spanner database:
- Project: {PROJECT_ID}
- Instance: {SPANNER_INSTANCE_ID}
- Database: {SPANNER_DATABASE_ID}

You can help users by:
1. Listing available tables in the database
2. Showing table schemas
3. Running SQL queries to retrieve data

When a user asks about data, first list the available tables, then examine
their schemas, and then construct appropriate SQL queries.

CRITICAL: Always use these EXACT string values when calling Spanner tools:
- project_id="{PROJECT_ID}" (NEVER use the numeric project number)
- instance_id="{SPANNER_INSTANCE_ID}"
- database_id="{SPANNER_DATABASE_ID}"

If you encounter permission errors, explain to the user that they may not
have access to the requested resource due to IAM or fine-grained access
control restrictions.
"""

def debug_patches(tool_context) -> dict:
    """Diagnostic tool: checks all monkey-patches and Spanner connectivity.

    ALWAYS call this tool first before any other tool.
    """
    import google.cloud.spanner_v1.database
    import google.cloud.spanner_v1.instance
    from google.cloud.spanner_admin_database_v1.types import DatabaseDialect
    from .auth_wrapper import (
        _safe_database_dialect,
        _safe_reload,
        _safe_exists,
        _patched_instance_database,
        get_bearer_token,
        BearerTokenCredentialsManager,
    )

    results = {}

    # 1. Check all patches
    db_class = google.cloud.spanner_v1.database.Database
    inst_class = google.cloud.spanner_v1.instance.Instance

    prop = getattr(db_class, 'database_dialect', None)
    results["dialect_prop_patched"] = isinstance(prop, property) and prop.fget is _safe_database_dialect
    results["reload_patched"] = db_class.reload is _safe_reload
    results["exists_patched"] = db_class.exists is _safe_exists
    results["instance_db_patched"] = inst_class.database is _patched_instance_database
    results["all_patches_applied"] = all([
        results["dialect_prop_patched"],
        results["reload_patched"],
        results["exists_patched"],
        results["instance_db_patched"],
    ])

    # 2. Env vars
    results["GOOGLE_CLOUD_PROJECT"] = os.environ.get("GOOGLE_CLOUD_PROJECT", "NOT_SET")
    results["PROJECT_ID_resolved"] = PROJECT_ID

    # 3. Token check
    mgr = BearerTokenCredentialsManager()
    state_token = mgr._extract_token_from_state(tool_context)
    token = get_bearer_token() or state_token
    results["has_token"] = bool(token)

    # 4. Test with actual Spanner
    if token:
        try:
            import google.cloud.spanner as spanner
            import google.oauth2.credentials
            creds = google.oauth2.credentials.Credentials(token=token)
            client = spanner.Client(project="switon-gsd-demos", credentials=creds)
            instance = client.instance("adk-auth-exp")
            database = instance.database("demo-db")
            results["db_dialect_value"] = str(database._database_dialect)
            results["db_name"] = database.name

            # Test INFORMATION_SCHEMA directly
            with database.snapshot() as snapshot:
                rs = snapshot.execute_sql(
                    "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ''"
                )
                tables = [row[0] for row in rs]
            results["tables"] = tables

            # Test ADK list_table_names
            from google.adk.tools.spanner import metadata_tool
            tool_result = metadata_tool.list_table_names(
                project_id="switon-gsd-demos",
                instance_id="adk-auth-exp",
                database_id="demo-db",
                credentials=creds,
            )
            results["adk_list_tables"] = tool_result

            # Test ADK get_table_schema
            schema_result = metadata_tool.get_table_schema(
                project_id="switon-gsd-demos",
                instance_id="adk-auth-exp",
                database_id="demo-db",
                table_name="employees",
                credentials=creds,
            )
            results["adk_get_schema_status"] = schema_result.get("status")

            # Test ADK execute_sql via the function
            from google.adk.tools.spanner import query_tool
            from google.adk.tools.spanner.settings import SpannerToolSettings
            settings = SpannerToolSettings(max_executed_query_result_rows=5)
            exec_fn = query_tool.get_execute_sql(settings)
            # The function has specific signature, call manually
            from google.adk.tools.spanner import utils
            sql_result = utils.execute_sql(
                project_id="switon-gsd-demos",
                instance_id="adk-auth-exp",
                database_id="demo-db",
                query="SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ''",
                credentials=creds,
                settings=settings,
                tool_context=tool_context,
            )
            results["adk_execute_sql"] = sql_result

            # Test spanner lib version
            import google.cloud.spanner_v1
            results["spanner_lib_version"] = getattr(google.cloud.spanner_v1, '__version__', 'unknown')

        except Exception as e:
            results["error"] = str(e)[:500]

    return results


root_agent = Agent(
    name="spanner_data_agent",
    model="gemini-2.5-flash",
    description="An agent that queries Spanner databases with user credential propagation.",
    instruction=AGENT_INSTRUCTION + "\n\nIMPORTANT: ALWAYS call debug_patches first before any other tool.",
    tools=[spanner_toolset, debug_patches],
    before_tool_callback=normalize_project_id_callback,
)
