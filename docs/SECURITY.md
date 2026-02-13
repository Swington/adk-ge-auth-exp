# Security Architecture & Spanner Isolation

This document outlines the security architecture for the ADK Auth Experiment, specifically focusing on how user identity is propagated to Cloud Spanner to enforce Row-Level Security (RLS) and Fine-Grained Access Control (FGAC).

## Overview

The system ensures that the end-user's identity is preserved from the entry point (Cloud Run) down to the database layer (Cloud Spanner). This allows Spanner to enforce access control policies based on the actual user rather than a generic service account.

## Authentication Flow

1.  **Client**: Authenticates with Google Cloud (e.g., via `gcloud auth print-identity-token`).
2.  **Cloud Run**: Receives the request with the user's OIDC ID Token.
3.  **Agent (`spanner_agent`)**:
    *   Extracts the ID Token from the `Authorization` header.
    *   Validates the token.
    *   Uses **Service Account Impersonation** (or direct credential exchange if configured) to obtain a short-lived access token representing the user (or a service account representing the user's role).
    *   *Current Implementation*: The agent uses `google.auth.impersonated_credentials` to impersonate specific service accounts based on the user's identity or role mapping.

## Spanner Data Isolation

Spanner uses **Fine-Grained Access Control (FGAC)** to restrict access to data.

### Database Roles

The following database roles are defined in Spanner:

*   **`employees_reader`**:
    *   Can read from the `employees` table.
    *   **Cannot** read from the `salaries` table.
    *   Assigned to standard users.

*   **`admin`** (Implicit/Full Access):
    *   Can read/write all tables, including `salaries`.
    *   Assigned to administrative users.

### Service Accounts

To map users to these roles, we utilize distinct Service Accounts:

1.  **`user1-full-access`**:
    *   Represents an Admin user.
    *   Has full IAM permissions on the Spanner database.
2.  **`user3-fgac`**:
    *   Represents a Standard user.
    *   Has the `spanner.databaseRoleUser` IAM role.
    *   Is configured to assume the `employees_reader` database role upon connection.
3.  **`user2-no-access`**:
    *   Represents a user with no access.
    *   Has no IAM permissions on the Spanner database.

## Verification

We verify this isolation using integration tests (`tests/integration/test_spanner_isolation.py`).

### Test Cases

1.  **Admin Access**:
    *   Impersonates `user1-full-access`.
    *   Verifies access to `employees` table.
    *   Verifies access to `salaries` table.
2.  **Standard User Access**:
    *   Impersonates `user3-fgac`.
    *   Verifies access to `employees` table.
    *   Verifies **denial** of access to `salaries` table (Expects `PermissionDenied`).
3.  **No Access**:
    *   Impersonates `user2-no-access`.
    *   Verifies **denial** of connection or query execution.

## Future Improvements

*   **Direct Principal Propagation**: Instead of mapping to Service Accounts, pass the user's identity directly to Spanner if supported by the specific configuration (e.g., using FGAC with principal-based policies directly).
*   **Dynamic Role Mapping**: Implement a more robust mapping logic in the agent to select the correct target service account based on group membership.
