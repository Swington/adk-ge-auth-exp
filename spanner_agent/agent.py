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

root_agent = Agent(
    name="spanner_data_agent",
    model="gemini-2.5-flash",
    description="An agent that queries Spanner databases with user credential propagation.",
    instruction=AGENT_INSTRUCTION,
    tools=[spanner_toolset],
    before_tool_callback=normalize_project_id_callback,
)
