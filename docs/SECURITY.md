# Security Architecture & Spanner Isolation

This document outlines the security architecture, specifically how user identity is propagated to Cloud Spanner to enforce Fine-Grained Access Control (FGAC).

## Overview

The system preserves the end-user's identity from the entry point (Cloud Run) down to the database layer (Cloud Spanner). This allows Spanner to enforce access control policies based on the actual user rather than a generic service account.

## Authentication Flow

1. **Gemini Enterprise** authenticates the user via OAuth and forwards their access token.
2. **Cloud Run** receives the request with both an identity token (`Authorization`) and the user's OAuth token (`X-User-Authorization`).
3. **AuthTokenExtractorMiddleware** extracts the user's Bearer token and stores it in a ContextVar.
4. **BearerTokenSpannerToolset** reads the token from the ContextVar and uses it as the Spanner credential.
5. **Cloud Spanner** enforces IAM and FGAC policies based on the user's identity.

## Spanner Data Isolation

Spanner uses **Fine-Grained Access Control (FGAC)** to restrict access to data.

### Database Roles

Define database roles in Spanner to control per-table access:

- **Restricted reader role** (e.g. `employees_reader`):
  - Can read from specific tables only.
  - Cannot read from sensitive tables.
  - Assigned to users via `USER_DATABASE_ROLE_MAP`.

- **Full access** (no database role):
  - Users not in `USER_DATABASE_ROLE_MAP` connect without a database role.
  - Standard IAM permissions apply.

### Access Levels

The system supports three access patterns:

1. **Full access user**: Has IAM permissions on the Spanner database, connects without a database role, can read all tables.
2. **FGAC user**: Has `spanner.databaseRoleUser` IAM role, connects with a specific database role that restricts table access.
3. **No access user**: Has no IAM permissions on the Spanner database, receives `PermissionDenied`.

## Verification

Integration tests (`tests/integration/test_spanner_isolation.py`) verify isolation using service account impersonation:

1. **Full access**: Verifies read access to all tables.
2. **FGAC**: Verifies read access to permitted tables and denial on restricted tables.
3. **No access**: Verifies denial of connection or query execution.

## Security Considerations

- The Cloud Run service account itself should **not** have Spanner access. All Spanner calls use the end-user's propagated credentials.
- `--no-invoker-iam-check` is required on Cloud Run because Gemini Enterprise sends the user's OAuth token (not an identity token) in the `Authorization` header.
- The `email` OAuth scope is required to resolve the user's email for FGAC database role lookup.
