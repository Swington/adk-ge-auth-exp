# ADK Spanner Agent — Per-User Auth & FGAC Demo

A Google [ADK](https://google.github.io/adk-docs/) agent that queries Cloud Spanner, deployable on **Cloud Run** (A2A) or **Agent Engine** (Vertex AI). Connected to Gemini Enterprise for end-user credential propagation. Demonstrates **per-user credential propagation** and **Spanner Fine-Grained Access Control (FGAC)** so that different users see different data depending on their IAM permissions.

## Problem Statement

When Gemini Enterprise invokes an ADK agent, the end-user's OAuth access token is forwarded. By default ADK's `SpannerToolset` uses the service account's credentials for all Spanner calls, meaning every user gets the same access level. This project shows how to:

1. **Extract** the end-user's Bearer token (from HTTP headers on Cloud Run, or from session state on Agent Engine).
2. **Propagate** that token as the Spanner credential so IAM is enforced per-user.
3. **Inject** a Spanner `database_role` for users who require FGAC.

## Architecture

The agent supports two deployment modes with a shared credential manager:

### Cloud Run (A2A protocol)

```
Gemini Enterprise
       │  POST /a2a/spanner_agent  (A2A JSON-RPC)
       │  Authorization: Bearer <identity-token>
       │  X-User-Authorization: Bearer <user-token>
       ▼
  AuthTokenExtractorMiddleware
    ├─ extracts Bearer token → ContextVar
    ├─ resolves user email → database_role
    └─ resets both after the request
       │
  RootToA2ARewriteMiddleware
    └─ rewrites / → /a2a/spanner_agent
       │
  FastAPI (ADK) → BearerTokenSpannerToolset
    └─ reads token from ContextVar
       │
  Cloud Spanner (IAM + FGAC per user)
```

### Agent Engine (Vertex AI managed runtime)

```
Gemini Enterprise / AgentSpace
       │  streaming_agent_run_with_events(request_json)
       │  request.authorizations = {auth_id: {access_token: "..."}}
       ▼
  AdkApp._init_session()
    └─ stores token in session.state[auth_id]
       │
  Agent → BearerTokenSpannerToolset
    └─ reads token from tool_context.state
    └─ lazily resolves email → database_role
       │
  Cloud Spanner (IAM + FGAC per user)
```

## Test Users

| User | SA for integration tests | Spanner Access |
|------|--------------------------|----------------|
| `adk-auth-exp-1@switon.altostrat.com` | `user1-full-access@...iam.gserviceaccount.com` | Full read (employees + salaries) |
| `adk-auth-exp-2@switon.altostrat.com` | `user2-no-access@...iam.gserviceaccount.com` | No access (PermissionDenied) |
| `adk-auth-exp-3@switon.altostrat.com` | `user3-fgac@...iam.gserviceaccount.com` | FGAC: employees only, denied on salaries |

## Deployed Resources

| Resource | Value |
|----------|-------|
| Project | `switon-gsd-demos` |
| Cloud Run service | `adk-spanner-agent` (us-central1) |
| Cloud Run URL | `https://adk-spanner-agent-535816463745.us-central1.run.app` |
| Cloud Run SA | `adk-spanner-agent@switon-gsd-demos.iam.gserviceaccount.com` (no Spanner access) |
| Agent Engine | `projects/535816463745/locations/us-central1/reasoningEngines/954924749211828224` |
| Spanner instance | `adk-auth-exp` (us-central1) |
| Spanner database | `demo-db` |

## Database Schema

**`employees`** — `employee_id` (INT64 PK), `name`, `department`, `email`, `hire_date`

**`salaries`** — `employee_id` (INT64 PK), `base_salary`, `bonus`, `currency`, `effective_date` (PK)

### FGAC Setup

- Database role `employees_reader` has `SELECT ON TABLE employees` only.
- The role also inherits `spanner_info_reader` for schema introspection.
- User 3's IAM binding for `roles/spanner.databaseRoleUser` is conditioned to only allow the `employees_reader` role.

## Project Structure

```
adk-auth-exp/
├── main.py                          # Cloud Run entry point (middleware + FastAPI)
├── Dockerfile                       # Cloud Run container
├── pyproject.toml                   # Dependencies (uv)
├── spanner_agent/
│   ├── __init__.py
│   ├── agent.py                     # ADK Agent definition
│   ├── agent.json                   # A2A agent card
│   ├── agent_engine_app.py          # Agent Engine entry point (AdkApp)
│   └── auth_wrapper.py              # Bearer token credential manager, FGAC, middleware
└── tests/
    ├── test_auth_wrapper.py          # Unit tests (mocked, no GCP calls)
    └── integration/
        ├── test_spanner_isolation.py # Direct Spanner access tests via SA impersonation
        └── test_deployed_a2a.py      # End-to-end A2A tests against Cloud Run
```

## Running Tests

### Unit tests (no GCP credentials required)

```bash
uv run python -m pytest tests/test_auth_wrapper.py -v
```

### Integration tests — direct Spanner isolation

Requires ADC with `serviceAccountTokenCreator` on the test SAs:

```bash
uv run python -m pytest tests/integration/test_spanner_isolation.py -v
```

### Integration tests — deployed A2A agent

Requires a deployed Cloud Run service and `gcloud auth print-identity-token`:

```bash
uv run python -m pytest tests/integration/test_deployed_a2a.py -v -s
```

## Local Development

```bash
# Start the agent locally (requires ADC configured)
GOOGLE_CLOUD_PROJECT=switon-gsd-demos \
GOOGLE_GENAI_USE_VERTEXAI=True \
uv run uvicorn main:app --host 127.0.0.1 --port 8080
```

## Deploying to Cloud Run

```bash
gcloud run deploy adk-spanner-agent \
  --source . \
  --project switon-gsd-demos \
  --region us-central1 \
  --service-account adk-spanner-agent@switon-gsd-demos.iam.gserviceaccount.com \
  --no-invoker-iam-check \
  --set-env-vars GOOGLE_CLOUD_PROJECT=switon-gsd-demos,GOOGLE_GENAI_USE_VERTEXAI=True
```

`--no-invoker-iam-check` is required because Gemini Enterprise sends the user's OAuth token in `Authorization`, and Cloud Run IAM would otherwise reject it (it's not an identity token).

## Deploying to Agent Engine

```bash
adk deploy agent_engine \
  --project=switon-gsd-demos \
  --region=us-central1 \
  --trace_to_cloud \
  spanner_agent
```

Agent Engine deployment uses `spanner_agent/agent_engine_app.py` as the entry point. The `AdkApp` wrapper provides session management and the `streaming_agent_run_with_events` method for AgentSpace invocation. User credentials are passed via the `authorizations` field in the request and stored in session state.

## Connecting to Gemini Enterprise

1. Create an OAuth authorization resource (Discovery Engine API `v1alpha`) with `email` scope.
2. Create an agent in Gemini Enterprise pointing to the Cloud Run URL.
3. Link the authorization resource to the agent.
4. Users are prompted to authorize on first interaction; subsequent requests carry their OAuth token automatically.

The `email` scope is critical — without it, the middleware cannot resolve the user's email to look up their FGAC database role.
