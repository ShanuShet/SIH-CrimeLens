import os
import sys
import unittest
import json
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal, migrate_case_fields
from app.models import Case, Entity, Relationship, Document, EvidenceIntegrity, BlockchainBlock, User
from app.services.graph_service import (
    resolve_existing_entity,
    normalize_name,
    normalize_phone,
    normalize_account,
    normalize_vehicle,
    normalize_email,
    upsert_graph
)
from app.services.risk_service import compute_case_risk, risk_band

class TestSupervisorAudit(unittest.TestCase):
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

        # Ensure we have test cases for case isolation
        cls.test_case_a = cls.db.query(Case).filter(Case.title == "Audit Test Case Alpha").first()
        if not cls.test_case_a:
            cls.test_case_a = Case(
                title="Audit Test Case Alpha",
                reference_id="TC-AUD-A-001",
                status="Open",
                risk="High",
                description="Audit Case Alpha for entity resolution & isolation"
            )
            cls.db.add(cls.test_case_a)
            cls.db.commit()
            cls.db.refresh(cls.test_case_a)

        cls.test_case_b = cls.db.query(Case).filter(Case.title == "Audit Test Case Beta").first()
        if not cls.test_case_b:
            cls.test_case_b = Case(
                title="Audit Test Case Beta",
                reference_id="TC-AUD-B-002",
                status="Open",
                risk="Medium",
                description="Audit Case Beta for entity resolution & isolation"
            )
            cls.db.add(cls.test_case_b)
            cls.db.commit()
            cls.db.refresh(cls.test_case_b)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def setUp(self):
        self.db.rollback()

    def tearDown(self):
        self.db.rollback()

    # ----------------------------------------------------------------------
    # 8. ENTITY RESOLUTION TEST MATRIX (15 Mandatory Tests)
    # ----------------------------------------------------------------------

    def test_matrix_01_same_name_only(self):
        """1. Same name only: When candidate exists with same name but no identifiers, returns AMBIGUOUS."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        e1 = Entity(
            key=f"person:vikram_{u}",
            name=f"Vikram Sethi {u}",
            label="Person",
            case_id=case_id
        )
        self.db.add(e1)
        self.db.commit()
        self.db.refresh(e1)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Vikram Sethi {u}", "label": "Person", "key": f"person:candidate_{u}"},
            case_id=case_id
        )
        self.assertEqual(status, "AMBIGUOUS")
        self.assertIn("Name matches", reason)
        print(f"Matrix Test 1 [PASS]: Input='Vikram Sethi {u}' -> Result={status} ({reason}) | Case={case_id}")

    def test_matrix_02_same_name_same_phone(self):
        """2. Same name + same phone: Deterministically MATCHED."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        phone_raw = f"98{uuid4().int % 100000000:08d}"
        phone_norm = normalize_phone(phone_raw)
        e = Entity(
            key=f"person:anand_{u}",
            name=f"Anand Sharma {u}",
            label="Person",
            phone=phone_norm,
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Anand Sharma {u}", "label": "Person", "phone": f"+91 {phone_raw}", "key": f"person:cand_{u}"},
            case_id=case_id
        )
        self.assertIn(status, ["EXACT_MATCH", "MATCHED"])
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, e.id)
        print(f"Matrix Test 2 [PASS]: Input='Anand Sharma {u}'+'+91 {phone_raw}' -> Result={status} ({reason}) | Entity ID={matched.id}")

    def test_matrix_03_same_name_different_phone(self):
        """3. Same name + different phone: Must NOT merge -> NEW_ENTITY."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        phone1 = f"91{uuid4().int % 100000000:08d}"
        phone2 = f"81{uuid4().int % 100000000:08d}"
        e = Entity(
            key=f"person:ravi_{u}",
            name=f"Ravi Kumar {u}",
            label="Person",
            phone=normalize_phone(phone1),
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Ravi Kumar {u}", "label": "Person", "phone": phone2, "key": f"person:cand_{u}"},
            case_id=case_id
        )
        self.assertEqual(status, "NEW_ENTITY")
        self.assertIsNone(matched)
        print(f"Matrix Test 3 [PASS]: Input='Ravi Kumar {u}'+'{phone2}' -> Result={status} ({reason})")

    def test_matrix_04_same_name_same_email(self):
        """4. Same name + same email: Deterministically MATCHED."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        e = Entity(
            key=f"person:sunil_{u}",
            name=f"Sunil Verma {u}",
            label="Person",
            email=normalize_email(f"sunil.{u}@example.com"),
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Sunil Verma {u}", "label": "Person", "email": f"SUNIL.{u.upper()}@EXAMPLE.COM", "key": f"person:cand_{u}"},
            case_id=case_id
        )
        self.assertIn(status, ["EXACT_MATCH", "MATCHED"])
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, e.id)
        print(f"Matrix Test 4 [PASS]: Input='Sunil Verma {u}' email -> Result={status} ({reason}) | Entity ID={matched.id}")

    def test_matrix_05_same_name_different_email(self):
        """5. Same name + different email: Must NOT merge -> NEW_ENTITY."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        e = Entity(
            key=f"person:pooja_{u}",
            name=f"Pooja Mehta {u}",
            label="Person",
            email=normalize_email(f"pooja.{u}.1@corp.in"),
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Pooja Mehta {u}", "label": "Person", "email": f"pooja.{u}.2@corp.in", "key": f"person:cand_{u}"},
            case_id=case_id
        )
        self.assertEqual(status, "NEW_ENTITY")
        self.assertIsNone(matched)
        print(f"Matrix Test 5 [PASS]: Input='Pooja Mehta {u}' diff email -> Result={status} ({reason})")

    def test_matrix_06_different_name_formatting(self):
        """6. Different name formatting: "Ravi Kumar", " ravi kumar ", "RAVI KUMAR" normalizes identically."""
        n1 = normalize_name("Ravi Kumar")
        n2 = normalize_name("   ravi kumar   ")
        n3 = normalize_name("RAVI KUMAR")
        self.assertEqual(n1, "ravi kumar")
        self.assertEqual(n1, n2)
        self.assertEqual(n2, n3)
        print(f"Matrix Test 6 [PASS]: Name normalization consistent: '{n1}' == '{n2}' == '{n3}'")

    def test_matrix_07_phone_formatting_variations(self):
        """7. Phone formatting variations: "+91 9000000001", "919000000001", "9000000001"."""
        p1 = normalize_phone("+91 9000000001")
        p2 = normalize_phone("919000000001")
        p3 = normalize_phone("9000000001")
        self.assertEqual(p1, "9000000001")
        self.assertEqual(p1, p2)
        self.assertEqual(p2, p3)
        print(f"Matrix Test 7 [PASS]: Phone normalization consistent: '{p1}' == '{p2}' == '{p3}'")

    def test_matrix_08_same_account(self):
        """8. Same account: Matches BankAccount entity exactly."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        acc_norm = normalize_account(f"SBIN0001234-{u}")
        e = Entity(
            key=f"bankaccount:sbin_{u}",
            name=f"SBIN0001234-{u}",
            label="BankAccount",
            account=acc_norm,
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"SBIN0001234-{u}", "label": "BankAccount", "account": f"sbin0001234-{u}", "key": f"acc:cand_{u}"},
            case_id=case_id
        )
        self.assertIn(status, ["EXACT_MATCH", "MATCHED"])
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, e.id)
        print(f"Matrix Test 8 [PASS]: Input account='sbin0001234-{u}' -> Result={status} ({reason}) | Entity ID={matched.id}")

    def test_matrix_09_same_vehicle(self):
        """9. Same vehicle: Matches Vehicle entity with normalized registration."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:4].upper()
        veh_norm = normalize_vehicle(f"DL-01-AB-{u}")
        e = Entity(
            key=f"vehicle:dl_{u}",
            name=f"DL-01-AB-{u}",
            label="Vehicle",
            vehicle=veh_norm,
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"dl 01 ab {u}", "label": "Vehicle", "vehicle": f"dl-01-ab-{u}", "key": f"veh:cand_{u}"},
            case_id=case_id
        )
        self.assertIn(status, ["EXACT_MATCH", "MATCHED"])
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, e.id)
        print(f"Matrix Test 9 [PASS]: Input vehicle='dl 01 ab {u}' -> Result={status} ({reason}) | Entity ID={matched.id}")

    def test_matrix_10_missing_optional_attributes(self):
        """10. Missing optional attributes: Handles entities gracefully with no email/phone/account."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        e = Entity(
            key=f"location:wh_{u}",
            name=f"Warehouse Sector {u}",
            label="Location",
            case_id=case_id
        )
        self.db.add(e)
        self.db.commit()
        self.db.refresh(e)

        matched, status, reason = resolve_existing_entity(
            self.db,
            {"name": f"Warehouse Sector {u}", "label": "Location", "key": f"loc:cand_{u}"},
            case_id=case_id
        )
        self.assertIn(status, ["EXACT_MATCH", "PROBABLE_MATCH", "MATCHED"])
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, e.id)
        print(f"Matrix Test 10 [PASS]: Missing optional attributes handled -> Result={status} | Entity ID={matched.id}")

    def test_matrix_11_duplicate_document(self):
        """11. Duplicate document: Ingesting the same entity from a second batch resolves into existing entity."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        name = f"Deepak Joshi {u}"
        phone = f"93{uuid4().int % 100000000:08d}"
        upsert_graph(
            self.db,
            [{"key": f"p:deepak_1_{u}", "name": name, "label": "Person", "phone": phone}],
            [],
            case_id=case_id
        )
        self.db.commit()

        count_before = self.db.query(Entity).filter(
            Entity.name == name, Entity.case_id == case_id
        ).count()

        upsert_graph(
            self.db,
            [{"key": f"p:deepak_2_{u}", "name": name, "label": "Person", "phone": f"+91-{phone}"}],
            [],
            case_id=case_id
        )
        self.db.commit()

        count_after = self.db.query(Entity).filter(
            Entity.name == name, Entity.case_id == case_id
        ).count()
        self.assertEqual(count_before, 1)
        self.assertEqual(count_after, 1, "Duplicate entity across batches must resolve to the same entity record")
        print(f"Matrix Test 11 [PASS]: Same entity from duplicate ingestion resolved cleanly: Entity Count={count_after}")

    def test_matrix_12_same_entity_across_multiple_documents(self):
        """12. Same entity across multiple documents merges and updates attributes."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        name = f"Kavita Rao {u}"
        phone = f"94{uuid4().int % 100000000:08d}"
        upsert_graph(
            self.db,
            [{"key": f"p:kavita_1_{u}", "name": name, "label": "Person", "phone": phone}],
            [],
            case_id=case_id
        )
        self.db.commit()

        upsert_graph(
            self.db,
            [{"key": f"p:kavita_2_{u}", "name": name, "label": "Person", "phone": phone, "email": f"kavita_{u}@investigation.in"}],
            [],
            case_id=case_id
        )
        self.db.commit()

        ent = self.db.query(Entity).filter(Entity.name == name, Entity.case_id == case_id).first()
        self.assertIsNotNone(ent)
        self.assertEqual(ent.phone, phone)
        self.assertEqual(ent.email, f"kavita_{u}@investigation.in")
        print(f"Matrix Test 12 [PASS]: Multi-document enrichment verified: Phone={ent.phone}, Email={ent.email}")

    def test_matrix_13_same_name_across_different_cases(self):
        """13. Same name across different cases: Case isolation strictly maintained."""
        case_a_id = self.test_case_a.id
        case_b_id = self.test_case_b.id
        u = uuid4().hex[:6]
        name = f"Rajesh Khanna {u}"
        phone = f"95{uuid4().int % 100000000:08d}"

        upsert_graph(
            self.db,
            [{"key": f"p:rajesh_a_{u}", "name": name, "label": "Person", "phone": phone}],
            [],
            case_id=case_a_id
        )
        upsert_graph(
            self.db,
            [{"key": f"p:rajesh_b_{u}", "name": name, "label": "Person", "phone": phone}],
            [],
            case_id=case_b_id
        )
        self.db.commit()

        ent_a = self.db.query(Entity).filter(Entity.name == name, Entity.case_id == case_a_id).first()
        ent_b = self.db.query(Entity).filter(Entity.name == name, Entity.case_id == case_b_id).first()
        self.assertIsNotNone(ent_a)
        self.assertIsNotNone(ent_b)
        self.assertNotEqual(ent_a.id, ent_b.id, "Entities across different cases must NEVER merge!")
        self.assertEqual(ent_a.case_id, case_a_id)
        self.assertEqual(ent_b.case_id, case_b_id)
        print(f"Matrix Test 13 [PASS]: Case isolation verified: Case A ID={ent_a.id} != Case B ID={ent_b.id}")

    def test_matrix_14_two_identical_names_different_identifiers(self):
        """14. Two identical names with different identifiers remain separate."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        name = f"Amit Patel {u}"
        phone1 = f"96{uuid4().int % 100000000:08d}"
        phone2 = f"97{uuid4().int % 100000000:08d}"

        upsert_graph(
            self.db,
            [{"key": f"p:amit_1_{u}", "name": name, "label": "Person", "phone": phone1}],
            [],
            case_id=case_id
        )
        upsert_graph(
            self.db,
            [{"key": f"p:amit_2_{u}", "name": name, "label": "Person", "phone": phone2}],
            [],
            case_id=case_id
        )
        self.db.commit()

        amits = self.db.query(Entity).filter(Entity.name == name, Entity.case_id == case_id).all()
        self.assertGreaterEqual(len(amits), 2)
        phones = {a.phone for a in amits}
        self.assertIn(phone1, phones)
        self.assertIn(phone2, phones)
        print(f"Matrix Test 14 [PASS]: Two identical names with different phones -> distinct entities: {[a.id for a in amits]}")

    def test_matrix_15_three_identical_names_different_identifiers(self):
        """15. Three identical names with different identifiers remain three separate entities."""
        case_id = self.test_case_a.id
        u = uuid4().hex[:6]
        name = f"Suresh Nair {u}"
        em1 = f"suresh1_{u}@kerala.in"
        em2 = f"suresh2_{u}@kerala.in"
        em3 = f"suresh3_{u}@kerala.in"

        upsert_graph(
            self.db,
            [{"key": f"p:suresh_1_{u}", "name": name, "label": "Person", "email": em1}],
            [],
            case_id=case_id
        )
        upsert_graph(
            self.db,
            [{"key": f"p:suresh_2_{u}", "name": name, "label": "Person", "email": em2}],
            [],
            case_id=case_id
        )
        upsert_graph(
            self.db,
            [{"key": f"p:suresh_3_{u}", "name": name, "label": "Person", "email": em3}],
            [],
            case_id=case_id
        )
        self.db.commit()

        sureshs = self.db.query(Entity).filter(Entity.name == name, Entity.case_id == case_id).all()
        self.assertGreaterEqual(len(sureshs), 3)
        emails = {s.email for s in sureshs}
        self.assertIn(em1, emails)
        self.assertIn(em2, emails)
        self.assertIn(em3, emails)
        print(f"Matrix Test 15 [PASS]: Three identical names with distinct emails -> distinct entities: {[s.id for s in sureshs]}")

    # ----------------------------------------------------------------------
    # CASE PORTFOLIO & REAL DB COUNTS
    # ----------------------------------------------------------------------

    def test_case_portfolio_real_db_counts(self):
        """Verify GET /api/cases returns accurate database-derived counts."""
        self.db.commit()
        res = self.client.get("/api/cases")
        self.assertEqual(res.status_code, 200)
        cases = res.json()
        self.assertIsInstance(cases, list)
        self.assertGreater(len(cases), 0)

        for c in cases:
            self.assertIn("evidence_count", c)
            self.assertIn("entity_count", c)
            self.assertIn("relationship_count", c)
            # Verify against database directly
            cid = c["id"]
            real_docs = self.db.query(Document).filter(Document.case_id == cid).count()
            real_entities = self.db.query(Entity).filter(Entity.case_id == cid).count()
            real_rels = self.db.query(Relationship).filter(Relationship.case_id == cid).count()
            self.assertEqual(c["evidence_count"], real_docs)
            self.assertEqual(c["entity_count"], real_entities)
            self.assertEqual(c["relationship_count"], real_rels)
        print("[OK] Case Portfolio API returns real database counts for all cases")

    # ----------------------------------------------------------------------
    # EVIDENCE LOCKER: PREVIEW & DELETE
    # ----------------------------------------------------------------------

    def test_evidence_preview_and_delete_with_ledger(self):
        """Verify GET /api/documents/{id} preview and DELETE /api/documents/{id} with cryptographic ledger anchoring."""
        case_id = self.test_case_a.id
        test_doc = Document(
            filename="forensic_report_test.txt",
            case_id=case_id,
            doc_type="TEXT",
            file_extension=".txt",
            file_size=120,
            content="CONFIDENTIAL EVIDENCE: Suspect communications log.\nTransaction recorded: INR 50,00,000.",
            status="INGESTED"
        )
        self.db.add(test_doc)
        self.db.commit()
        self.db.refresh(test_doc)

        os.makedirs("storage", exist_ok=True)
        disk_path = os.path.join("storage", f"{test_doc.id}_{test_doc.filename}")
        with open(disk_path, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL EVIDENCE: Suspect communications log.\nTransaction recorded: INR 50,00,000.")

        integ = EvidenceIntegrity(
            document_id=test_doc.id,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="VERIFIED"
        )
        self.db.add(integ)
        self.db.commit()

        # 1. Preview Document
        res_view = self.client.get(f"/api/documents/{test_doc.id}")
        self.assertEqual(res_view.status_code, 200)
        view_data = res_view.json()
        self.assertEqual(view_data["filename"], "forensic_report_test.txt")
        self.assertIn("CONFIDENTIAL EVIDENCE", view_data["content_preview"])
        self.assertEqual(view_data["integrity_status"], "VERIFIED")

        # 2. Delete Document
        blocks_before = self.db.query(BlockchainBlock).count()
        res_del = self.client.delete(f"/api/documents/{test_doc.id}", headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(res_del.status_code, 200)
        del_data = res_del.json()
        self.assertTrue(del_data["ok"])

        # Check DB: document removed
        doc_in_db = self.db.query(Document).filter(Document.id == test_doc.id).first()
        self.assertIsNone(doc_in_db)

        # Check Ledger: EVIDENCE_DELETED block appended
        blocks_after = self.db.query(BlockchainBlock).count()
        self.assertEqual(blocks_after, blocks_before + 1)
        latest_block = self.db.query(BlockchainBlock).order_by(BlockchainBlock.id.desc()).first()
        payload = json.loads(latest_block.payload) if isinstance(latest_block.payload, str) else latest_block.payload
        self.assertEqual(payload.get("action"), "EVIDENCE_DELETED")
        self.assertIn(str(test_doc.id), payload.get("detail", ""))
        print("[OK] Evidence preview, deletion, and blockchain ledger appending verified")

    # ----------------------------------------------------------------------
    # RISK DETERMINISM & EXPLANATIONS
    # ----------------------------------------------------------------------

    def test_risk_determinism_and_bounds(self):
        """Risk calculation must be strictly deterministic, explainable, and bounded 0..100."""
        case_id = self.test_case_a.id
        calc1 = compute_case_risk(self.db, case_id=case_id)
        calc2 = compute_case_risk(self.db, case_id=case_id)
        calc3 = compute_case_risk(self.db, case_id=case_id)

        self.assertEqual(calc1["case"]["score"], calc2["case"]["score"])
        self.assertEqual(calc2["case"]["score"], calc3["case"]["score"])
        self.assertTrue(0.0 <= calc1["case"]["score"] <= 100.0)
        self.assertIsInstance(calc1["case"]["factors"], list)
        self.assertEqual(calc1["algorithm"], "weighted-sum-v1")
        print(f"[OK] Deterministic Risk verified: score={calc1['case']['score']}, factors={len(calc1['case']['factors'])}")

    # ----------------------------------------------------------------------
    # EVIDENCE LEDGER INTEGRITY VERIFICATION
    # ----------------------------------------------------------------------

    def test_ledger_verification(self):
        """Cryptographic ledger verification confirms the SHA-256 hash chain is intact."""
        res = self.client.post("/api/security/verify", headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["valid"], f"Ledger verification failed: {data}")
        self.assertGreater(data["checked_blocks"], 0)
        print(f"[OK] Cryptographic Ledger verified: {data['checked_blocks']} blocks valid")

if __name__ == "__main__":
    unittest.main()
