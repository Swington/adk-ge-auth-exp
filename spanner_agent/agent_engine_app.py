"""Agent Engine entry point for Vertex AI deployment.

This module is the ``entrypoint_module`` for Agent Engine. It wraps the
ADK agent with ``AdkApp`` which provides session management, telemetry,
and the ``streaming_agent_run_with_events`` method used by AgentSpace.

Deploy with::

    adk deploy agent_engine \
        --project=switon-gsd-demos \
        --region=us-central1 \
        spanner_agent
"""

import os

import vertexai
from vertexai.agent_engines import AdkApp

from .agent import root_agent

vertexai.init(
    project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
    location=os.environ.get("GOOGLE_CLOUD_LOCATION"),
)

adk_app = AdkApp(
    agent=root_agent,
    enable_tracing=True,
)
