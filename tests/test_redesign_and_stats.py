import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal, migrate_case_fields
from app.models import Case, Entity, Relationship, Document, User

class TestRedesignAndStats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        migrate_case_fields()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Login as Admin
        res = cls.client.post("/api/login", json={
            "username": "admin@crimelens.local",
            "password": "Admin@12345"
        })
        assert res.status_code == 200, f"Login failed: {res.text}"
        data = res.json()
        cls.csrf = data["csrf_token"]

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_public_home_page(self):
        """Test public home page at / renders home.html with zero private case data."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.text
        self.assertIn("CrimeLens", html)
        self.assertIn("Investigation Intelligence", html)
        self.assertIn("COMMAND CENTER", html)
        self.assertIn("INTEGRITY LEDGER", html)
        # Ensure zero private case names leaked
        cases = self.db.query(Case).all()
        for c in cases:
            if len(c.title) > 6:
                self.assertNotIn(f">{c.title}<", html)
        print("[OK] Public home page rendered without leaking private case data")

    def test_02_deep_routes_render_index(self):
        """Test all deep navigation routes render index.html successfully."""
        routes = ["/dashboard", "/cases", "/evidence", "/entities", "/relationships", "/graph", "/risk", "/assistant", "/audit"]
        for r in routes:
            res = self.client.get(r)
            self.assertEqual(res.status_code, 200, f"Route {r} failed with status {res.status_code}")
            self.assertIn("CRIME LENS", res.text)
            self.assertIn('id="appShell"', res.text)
        print("[OK] Deep routes (/dashboard, /cases, /evidence, /entities, etc.) verified")

    def test_03_total_cases_accuracy(self):
        """Test total_cases reflects actual database count with and without active case."""
        actual_count = self.db.query(Case).count()
        self.assertGreater(actual_count, 0, "Expected at least one case in DB")

        # Call stats without case_id
        res_global = self.client.get("/api/stats")
        self.assertEqual(res_global.status_code, 200)
        data_global = res_global.json()
        self.assertEqual(data_global["total_cases"], actual_count, "Global total_cases must match database count")

        # Call stats WITH a case_id (previously bugged to return 1)
        first_case = self.db.query(Case).first()
        res_scoped = self.client.get(f"/api/stats?case_id={first_case.id}")
        self.assertEqual(res_scoped.status_code, 200)
        data_scoped = res_scoped.json()
        # Must still match actual total cases count!
        self.assertEqual(data_scoped["total_cases"], actual_count, "Case-scoped stats must NOT collapse total_cases to 1")
        self.assertEqual(data_scoped["case_id"], first_case.id)
        self.assertIsNotNone(data_scoped["selected_case"])
        self.assertEqual(data_scoped["selected_case"]["id"], first_case.id)
        print(f"[OK] Total cases accuracy verified: DB={actual_count}, Global={data_global['total_cases']}, Scoped={data_scoped['total_cases']}")

    def test_04_create_and_delete_case_metric_trace(self):
        """Test creating and deleting a case properly increments and decrements total_cases."""
        initial_count = self.db.query(Case).count()

        # 1. Create a case
        res_create = self.client.post("/api/cases", json={
            "title": "Metric Validation Case Alpha",
            "reference_id": "VAL-ALPHA-999",
            "status": "Open",
            "risk": "High",
            "description": "Validating metrics trace"
        }, headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(res_create.status_code, 200)
        new_case_id = res_create.json()["id"]

        # 2. Check stats global and scoped
        res_stats_after = self.client.get("/api/stats")
        self.assertEqual(res_stats_after.json()["total_cases"], initial_count + 1)

        res_scoped_after = self.client.get(f"/api/stats?case_id={new_case_id}")
        self.assertEqual(res_scoped_after.json()["total_cases"], initial_count + 1)

        # 3. Delete case
        res_del = self.client.delete(f"/api/cases/{new_case_id}", headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(res_del.status_code, 200)

        # 4. Check stats decremented
        res_stats_final = self.client.get("/api/stats")
        self.assertEqual(res_stats_final.json()["total_cases"], initial_count)
        print("[OK] Complete metric lifecycle (create -> stats -> delete -> stats) verified")

    def test_05_entities_and_relationships_endpoints(self):
        """Test /api/entities and /api/relationships endpoints."""
        res_entities = self.client.get("/api/entities")
        self.assertEqual(res_entities.status_code, 200)
        entities = res_entities.json()
        self.assertIsInstance(entities, list)
        if entities:
            e = entities[0]
            self.assertIn("key", e)
            self.assertIn("name", e)
            self.assertIn("label", e)
            self.assertIn("resolution_status", e)

        res_rels = self.client.get("/api/relationships")
        self.assertEqual(res_rels.status_code, 200)
        rels = res_rels.json()
        self.assertIsInstance(rels, list)
        if rels:
            r = rels[0]
            self.assertIn("source", r)
            self.assertIn("target", r)
            self.assertIn("relation", r)
            self.assertIn("source_info", r)
            self.assertIn("target_info", r)
        print("[OK] /api/entities and /api/relationships endpoints verified")

    def test_06_risk_endpoint(self):
        """Test /api/risk returns deterministic explainable report."""
        first_case = self.db.query(Case).first()
        res_risk = self.client.get(f"/api/risk?case_id={first_case.id}")
        self.assertEqual(res_risk.status_code, 200)
        report = res_risk.json()
        self.assertIn("case", report)
        self.assertIn("entities", report)
        self.assertIn("algorithm", report)
        self.assertIn("high_risk_threshold", report)
        score = report["case"]["score"]
        self.assertTrue(0 <= score <= 100, f"Risk score {score} must be bounded 0-100")
        print(f"[OK] /api/risk verified: score={score}, threshold={report['high_risk_threshold']}")

if __name__ == "__main__":
    unittest.main()
