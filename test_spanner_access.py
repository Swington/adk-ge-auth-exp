"""Test Spanner access control for the three test service accounts."""

import google.auth
import google.auth.impersonated_credentials
from google.cloud import spanner

PROJECT_ID = "switon-gsd-demos"
INSTANCE_ID = "adk-auth-exp"
DATABASE_ID = "demo-db"

SERVICE_ACCOUNTS = {
    "User 1 (full access)": "user1-full-access@switon-gsd-demos.iam.gserviceaccount.com",
    "User 2 (no access)": "user2-no-access@switon-gsd-demos.iam.gserviceaccount.com",
    "User 3 (FGAC - employees only)": "user3-fgac@switon-gsd-demos.iam.gserviceaccount.com",
}

QUERIES = {
    "employees": "SELECT * FROM employees LIMIT 5",
    "salaries": "SELECT * FROM salaries LIMIT 5",
}


def get_impersonated_credentials(target_sa: str):
    source_credentials, _ = google.auth.default()
    return google.auth.impersonated_credentials.Credentials(
        source_credentials=source_credentials,
        target_principal=target_sa,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )


def test_query(client: spanner.Client, table_name: str, query: str, database_role: str = None):
    database = client.instance(INSTANCE_ID).database(DATABASE_ID, database_role=database_role)
    try:
        with database.snapshot() as snapshot:
            results = snapshot.execute_sql(query)
            rows = list(results)
            print(f"  {table_name}: OK - {len(rows)} rows returned")
            for row in rows[:2]:
                print(f"    {row}")
    except Exception as e:
        error_msg = str(e)
        if "PERMISSION_DENIED" in error_msg or "permission" in error_msg.lower():
            print(f"  {table_name}: PERMISSION DENIED - {error_msg[:150]}")
        else:
            print(f"  {table_name}: ERROR - {error_msg[:200]}")


def main():
    for user_label, sa_email in SERVICE_ACCOUNTS.items():
        print(f"\n{'='*60}")
        print(f"Testing as: {user_label}")
        print(f"  SA: {sa_email}")
        print(f"{'='*60}")

        creds = get_impersonated_credentials(sa_email)
        client = spanner.Client(project=PROJECT_ID, credentials=creds)

        database_role = None
        if "FGAC" in user_label:
            database_role = "employees_reader"
            print(f"  Using database role: {database_role}")

        for table_name, query in QUERIES.items():
            test_query(client, table_name, query, database_role=database_role)


if __name__ == "__main__":
    main()
