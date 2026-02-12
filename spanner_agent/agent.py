"""ADK Agent with Spanner Toolkit for auth propagation experiment."""

import os

import google.auth
from google.adk.agents import Agent
from google.adk.tools.spanner.settings import Capabilities, SpannerToolSettings
from google.adk.tools.spanner.spanner_credentials import SpannerCredentialsConfig
from google.adk.tools.spanner.spanner_toolset import SpannerToolset

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "switon-gsd-demos")
SPANNER_INSTANCE_ID = os.environ.get("SPANNER_INSTANCE_ID", "adk-auth-exp")
SPANNER_DATABASE_ID = os.environ.get("SPANNER_DATABASE_ID", "demo-db")

# Use Application Default Credentials.
# When deployed to Cloud Run, this uses the service account's identity.
# For user access propagation testing, the agent is invoked with the
# user's own credentials via the OAuth flow.
credentials, _ = google.auth.default(
    scopes=[
        "https://www.googleapis.com/auth/spanner.data",
        "https://www.googleapis.com/auth/spanner.admin",
    ]
)

spanner_toolset = SpannerToolset(
    credentials_config=SpannerCredentialsConfig(credentials=credentials),
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

Always use the project_id="{PROJECT_ID}", instance_id="{SPANNER_INSTANCE_ID}",
and database_id="{SPANNER_DATABASE_ID}" when calling Spanner tools.

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
)
