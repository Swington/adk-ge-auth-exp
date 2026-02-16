# ADK Spanner Agent — Per-User Auth & FGAC

A Google [ADK](https://google.github.io/adk-docs/) agent that queries Cloud Spanner, deployed on **Cloud Run** via A2A protocol. Demonstrates **per-user credential propagation** and **Spanner Fine-Grained Access Control (FGAC)** so that different users see different data depending on their IAM permissions.

## Problem Statement

When Gemini Enterprise invokes an ADK agent, the end-user's OAuth access token is forwarded. By default ADK's `SpannerToolset` uses the service account's credentials for all Spanner calls, meaning every user gets the same access level. This project shows how to:

1. **Extract** the end-user's Bearer token from HTTP headers on Cloud Run.
2. **Propagate** that token as the Spanner credential so IAM is enforced per-user.
3. **Inject** a Spanner `database_role` for users who require FGAC.

## Architecture

```
Gemini Enterprise
       |  POST /a2a/spanner_agent  (A2A JSON-RPC)
       |  Authorization: Bearer <identity-token>
       |  X-User-Authorization: Bearer <user-token>
       v
  AuthTokenExtractorMiddleware
    +- extracts Bearer token -> ContextVar
    +- resolves user email -> database_role
    +- resets both after the request
       |
  RootToA2ARewriteMiddleware
    +- rewrites / -> /a2a/spanner_agent
       |
  FastAPI (ADK) -> BearerTokenSpannerToolset
    +- reads token from ContextVar
       |
  Cloud Spanner (IAM + FGAC per user)
```

## Project Structure

```
.
+-- main.py                          # Cloud Run entry point (middleware + FastAPI)
+-- Dockerfile                       # Cloud Run container
+-- pyproject.toml                   # Dependencies (uv)
+-- .env.example                     # Environment variable template
+-- spanner_agent/
|   +-- __init__.py
|   +-- agent.py                     # ADK Agent definition
|   +-- agent.json                   # A2A agent card
|   +-- auth_wrapper.py              # Bearer token credential manager, FGAC, middleware
+-- tests/
    +-- test_auth_wrapper.py          # Unit tests (mocked, no GCP calls)
    +-- integration/
        +-- test_spanner_isolation.py # Direct Spanner access tests via SA impersonation
        +-- test_deployed_a2a.py      # End-to-end A2A tests against Cloud Run
```

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- A Google Cloud project with:
  - Cloud Spanner instance and database
  - Cloud Run API enabled
  - Vertex AI API enabled (for Gemini model)

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Your GCP project ID |
| `GOOGLE_GENAI_USE_VERTEXAI` | Set to `True` |
| `SPANNER_INSTANCE_ID` | Your Spanner instance ID |
| `SPANNER_DATABASE_ID` | Your Spanner database ID |

### Optional Environment Variables

| Variable | Format | Description |
|----------|--------|-------------|
| `PROJECT_NUMBER_MAP` | `num1=id1,num2=id2` | Maps project numbers to project IDs (prevents LLM errors when it sends numeric project IDs) |
| `USER_DATABASE_ROLE_MAP` | `email1=role1,email2=role2` | Maps user emails to Spanner FGAC database roles |

## Running Tests

### Unit tests (no GCP credentials required)

```bash
uv run python -m pytest tests/test_auth_wrapper.py -v
```

### Integration tests — direct Spanner isolation

Requires ADC with `serviceAccountTokenCreator` on the test SAs.
Set `TEST_SA_FULL_ACCESS`, `TEST_SA_NO_ACCESS`, and `TEST_SA_FGAC` env vars.

```bash
uv run python -m pytest tests/integration/test_spanner_isolation.py -v
```

### Integration tests — deployed A2A agent

Requires a deployed Cloud Run service. Set `CLOUD_RUN_SERVICE_URL` and the test SA env vars.

```bash
uv run python -m pytest tests/integration/test_deployed_a2a.py -v -s
```

## Local Development

```bash
uv run uvicorn main:app --host 127.0.0.1 --port 8080
```

## Deploying to Cloud Run

```bash
gcloud run deploy <your-service-name> \
  --source . \
  --project <your-project-id> \
  --region <your-region> \
  --service-account <your-service-account> \
  --no-invoker-iam-check \
  --set-env-vars GOOGLE_CLOUD_PROJECT=<your-project-id>,GOOGLE_GENAI_USE_VERTEXAI=True,SPANNER_INSTANCE_ID=<your-instance>,SPANNER_DATABASE_ID=<your-database>
```

`--no-invoker-iam-check` is required because Gemini Enterprise sends the user's OAuth token in `Authorization`, and Cloud Run IAM would otherwise reject it (it's not an identity token).

## Connecting to Gemini Enterprise

1. Create an OAuth authorization resource (Discovery Engine API `v1alpha`) with `email` scope.
2. Create an agent in Gemini Enterprise pointing to your Cloud Run URL.
3. Link the authorization resource to the agent.
4. Users are prompted to authorize on first interaction; subsequent requests carry their OAuth token automatically.

The `email` scope is critical — without it, the middleware cannot resolve the user's email to look up their FGAC database role.

## Setting Up FGAC (Optional)

To use Fine-Grained Access Control:

1. Create a database role in Spanner with restricted permissions:
   ```sql
   CREATE ROLE my_reader;
   GRANT SELECT ON TABLE my_table TO ROLE my_reader;
   ```
2. Grant `roles/spanner.databaseRoleUser` to the user's IAM identity, conditioned to the role.
3. Set `USER_DATABASE_ROLE_MAP` to map the user's email to the database role:
   ```
   USER_DATABASE_ROLE_MAP="user@example.com=my_reader"
   ```
