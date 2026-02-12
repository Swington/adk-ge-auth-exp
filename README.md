# ADK Spanner Auth Experiment

An ADK (Agent Development Kit) agent that uses the Spanner Toolkit to query Cloud Spanner, deployed on Cloud Run. Demonstrates user access propagation and fine-grained access control (FGAC).

## Architecture

```
User → Gemini Enterprise → Cloud Run (ADK Agent) → Spanner
                                |
                         Uses user's credentials
                         (NOT the Cloud Run SA)
```

## Deployed Resources

| Resource | Details |
|----------|---------|
| **Project** | `switon-gsd-demos` |
| **Cloud Run Service** | `adk-spanner-agent` (us-central1) |
| **Cloud Run URL** | `https://adk-spanner-agent-535816463745.us-central1.run.app` |
| **Cloud Run SA** | `adk-spanner-agent@switon-gsd-demos.iam.gserviceaccount.com` (NO Spanner access) |
| **Spanner Instance** | `adk-auth-exp` (us-central1) |
| **Spanner Database** | `demo-db` |

## Database Schema

### `employees` table
| Column | Type |
|--------|------|
| employee_id | INT64 (PK) |
| name | STRING(256) |
| department | STRING(128) |
| email | STRING(256) |
| hire_date | DATE |

### `salaries` table
| Column | Type |
|--------|------|
| employee_id | INT64 (PK) |
| base_salary | FLOAT64 |
| bonus | FLOAT64 |
| currency | STRING(8) |
| effective_date | DATE (PK) |

## Access Control Setup

### IAM Roles on Spanner Database `demo-db`

| User | IAM Role | Spanner DB Role | Access |
|------|----------|-----------------|--------|
| `adk-auth-exp-1@switon.altostrat.com` | `roles/spanner.databaseReader` | — | Full read on all tables |
| `adk-auth-exp-2@switon.altostrat.com` | (none) | — | No access |
| `adk-auth-exp-3@switon.altostrat.com` | `roles/spanner.fineGrainedAccessUser` + `roles/spanner.databaseRoleUser` (conditioned) | `employees_reader` | Read `employees` only; denied on `salaries` |

### Fine-Grained Access Control (FGAC)

- Database role `employees_reader` has `SELECT` on `employees` table only
- Database role also has `spanner_info_reader` system role for schema introspection
- User 3's `databaseRoleUser` binding uses an IAM condition: `resource.type == "spanner.googleapis.com/DatabaseRole" && resource.name.endsWith("/databaseRoles/employees_reader")`

### Cloud Run Service Account

The Cloud Run service account `adk-spanner-agent@switon-gsd-demos.iam.gserviceaccount.com` intentionally has **no Spanner access**. This ensures that user credential propagation is required — the agent cannot fall back to using the service account to access data.

## Connecting to Gemini Enterprise

To connect this ADK agent to Gemini Enterprise (Gemini for Google Cloud):

### Prerequisites
- A Gemini Enterprise instance in your Google Cloud project
- The Cloud Run service URL: `https://adk-spanner-agent-535816463745.us-central1.run.app`

### Steps

1. **Navigate to Gemini Enterprise** in the Google Cloud Console

2. **Register the agent as an extension/plugin**:
   - Go to Gemini Enterprise settings
   - Add a new agent/extension
   - Set the endpoint URL to: `https://adk-spanner-agent-535816463745.us-central1.run.app`
   - Configure authentication: use Google Cloud IAM authentication

3. **Configure user credential propagation**:
   - When setting up the agent in Gemini Enterprise, configure it to pass the user's OAuth token to the Cloud Run service
   - The agent needs the user's credentials (not the service account's) to query Spanner
   - This is the key mechanism for access control: Spanner enforces permissions based on who is making the query

4. **Grant Cloud Run invoker access** to your users:
   ```bash
   gcloud run services add-iam-policy-binding adk-spanner-agent \
     --project=switon-gsd-demos \
     --region=us-central1 \
     --member="user:USER_EMAIL" \
     --role="roles/run.invoker"
   ```

5. **Test with each user account**:
   - `adk-auth-exp-1@switon.altostrat.com`: Should be able to query both `employees` and `salaries` tables
   - `adk-auth-exp-2@switon.altostrat.com`: Should get permission denied on any Spanner query
   - `adk-auth-exp-3@switon.altostrat.com`: Should be able to query `employees` but get denied on `salaries`

### Important Note on User Credential Propagation

The current agent uses Application Default Credentials (ADC). For true user credential propagation through Gemini Enterprise, the agent code needs to be updated to extract and use the user's OAuth token from the incoming request. This can be done by:

1. **Using SpannerCredentialsConfig with OAuth flow** (client_id/client_secret) — the ADK framework handles the OAuth consent flow automatically
2. **Extracting the user's token from the request headers** — when Gemini Enterprise forwards requests, it includes the user's identity token

The key change in `spanner_agent/agent.py` would be switching from:
```python
credentials, _ = google.auth.default(...)
SpannerCredentialsConfig(credentials=credentials)
```
to:
```python
SpannerCredentialsConfig(
    client_id="YOUR_OAUTH_CLIENT_ID",
    client_secret="YOUR_OAUTH_CLIENT_SECRET",
    scopes=["https://www.googleapis.com/auth/spanner.data"],
)
```

This triggers the ADK OAuth flow, where each user authenticates with their own Google account.

## Running Tests

### Direct Spanner access test (using service account impersonation):
```bash
uv run python test_spanner_access.py
```

### Deployed agent test:
```bash
uv run python test_deployed_agent.py
```

### Local development:
```bash
GOOGLE_CLOUD_PROJECT=switon-gsd-demos GOOGLE_GENAI_USE_VERTEXAI=True adk web spanner_agent
```

## Project Structure

```
adk-auth-exp/
├── spanner_agent/
│   ├── __init__.py
│   └── agent.py          # ADK agent with SpannerToolset
├── test_spanner_access.py # Direct Spanner access control test
├── test_deployed_agent.py # Cloud Run deployed agent test
├── pyproject.toml         # uv-managed dependencies
├── .env                   # Environment variables
└── README.md              # This file
```
