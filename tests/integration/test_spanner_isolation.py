import os
import unittest

import google.auth
import google.auth.impersonated_credentials
from google.api_core.exceptions import PermissionDenied
from google.cloud import spanner

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
INSTANCE_ID = os.environ.get("SPANNER_INSTANCE_ID", "")
DATABASE_ID = os.environ.get("SPANNER_DATABASE_ID", "")

# Service Accounts — set via environment variables
SA_ADMIN = os.environ.get("TEST_SA_FULL_ACCESS", "")
SA_NO_ACCESS = os.environ.get("TEST_SA_NO_ACCESS", "")
SA_STANDARD = os.environ.get("TEST_SA_FGAC", "")

class TestSpannerIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_credentials, _ = google.auth.default()

    def get_client(self, target_sa):
        creds = google.auth.impersonated_credentials.Credentials(
            source_credentials=self.source_credentials,
            target_principal=target_sa,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return spanner.Client(project=PROJECT_ID, credentials=creds)

    def test_admin_access(self):
        """Admin should have full access."""
        print("\nTesting Admin Access...")
        client = self.get_client(SA_ADMIN)
        instance = client.instance(INSTANCE_ID)
        database = instance.database(DATABASE_ID)
        
        with database.snapshot(multi_use=True) as snapshot:
            # Can read employees
            results = list(snapshot.execute_sql("SELECT * FROM employees LIMIT 1"))
            self.assertGreaterEqual(len(results), 0)
            print("  Admin can read employees: OK")
            
            # Can read salaries
            results = list(snapshot.execute_sql("SELECT * FROM salaries LIMIT 1"))
            self.assertGreaterEqual(len(results), 0)
            print("  Admin can read salaries: OK")

    def test_standard_user_access(self):
        """Standard user (FGAC) should have restricted access."""
        print("\nTesting Standard User Access...")
        client = self.get_client(SA_STANDARD)
        instance = client.instance(INSTANCE_ID)
        # Must use the role
        database = instance.database(DATABASE_ID, database_role="employees_reader")
        
        with database.snapshot(multi_use=True) as snapshot:
            # Can read employees
            results = list(snapshot.execute_sql("SELECT * FROM employees LIMIT 1"))
            self.assertGreaterEqual(len(results), 0)
            print("  Standard User can read employees: OK")
            
            # Cannot read salaries
            with self.assertRaises(PermissionDenied):
                list(snapshot.execute_sql("SELECT * FROM salaries LIMIT 1"))
            print("  Standard User cannot read salaries: OK (PermissionDenied)")

    def test_no_access_user(self):
        """User with no access should fail to connect or query."""
        print("\nTesting No Access User...")
        client = self.get_client(SA_NO_ACCESS)
        instance = client.instance(INSTANCE_ID)
        database = instance.database(DATABASE_ID)
        
        # Should fail on session creation or query
        with self.assertRaises(PermissionDenied):
            with database.snapshot() as snapshot:
                list(snapshot.execute_sql("SELECT * FROM employees LIMIT 1"))
        print("  No Access User denied: OK (PermissionDenied)")

if __name__ == "__main__":
    unittest.main()
