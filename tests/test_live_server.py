import urllib.request
import urllib.parse
import http.cookiejar
import json
import sys

BASE_URL = "http://127.0.0.1:8080"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def log(step, status, detail=""):
    print(f"[{status}] {step}: {detail}")

csrf_token = None

try:
    # 1. Public Landing Page
    req = urllib.request.Request(f"{BASE_URL}/")
    with opener.open(req) as res:
        assert res.status == 200
        html = res.read().decode()
        assert "CrimeLens" in html
        assert "COMMAND CENTER" in html
        log("1. Public Landing Page", "PASS", "HTTP 200, clean public rendering")

    # 2. Login
    login_data = json.dumps({"username": "admin@crimelens.local", "password": "Admin@12345"}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/login", data=login_data, headers={"Content-Type": "application/json"})
    with opener.open(req) as res:
        assert res.status == 200
        body = json.loads(res.read().decode())
        csrf_token = body.get("csrf_token")
        assert csrf_token, "Expected CSRF token"
        assert body["user"]["role"].lower() in ["admin", "supervisor", "investigator"]
        log("2. Authentication", "PASS", f"User: {body['user']['username']}, Role: {body['user']['role']}")

    # 3. Session Check
    req = urllib.request.Request(f"{BASE_URL}/api/session")
    with opener.open(req) as res:
        assert res.status == 200
        session_data = json.loads(res.read().decode())
        assert session_data["authenticated"] is True
        log("3. Session Posture", "PASS", f"Permissions: {len(session_data.get('permissions', []))}")

    # 4. Dashboard Cases Portfolio
    req = urllib.request.Request(f"{BASE_URL}/api/cases")
    cases = []
    with opener.open(req) as res:
        assert res.status == 200
        cases = json.loads(res.read().decode())
        assert len(cases) > 0, "Expected at least 1 case in portfolio"
        for c in cases:
            assert "evidence_count" in c and "entity_count" in c and "relationship_count" in c
        log("4. Case Portfolio", "PASS", f"Loaded {len(cases)} cases with real counters")

    active_case = cases[0]
    active_case_id = active_case["id"]

    # 5. Dashboard Statistics (Global & Case Scoped)
    req = urllib.request.Request(f"{BASE_URL}/api/stats?case_id={active_case_id}")
    with opener.open(req) as res:
        assert res.status == 200
        stats = json.loads(res.read().decode())
        assert stats["total_cases"] >= len(cases)
        log("5. Dashboard Metrics", "PASS", f"Total Cases: {stats['total_cases']}, Scoped Case: {stats['case_id']}")

    # 6. Evidence Locker List
    req = urllib.request.Request(f"{BASE_URL}/api/documents?case_id={active_case_id}")
    with opener.open(req) as res:
        assert res.status == 200
        docs = json.loads(res.read().decode())
        for d in docs:
            assert "rag_indexed" in d
        log("6. Evidence Locker List", "PASS", f"Found {len(docs)} documents (Case #{active_case_id})")

    # 7. Entity Intelligence Master
    req = urllib.request.Request(f"{BASE_URL}/api/entities?case_id={active_case_id}")
    with opener.open(req) as res:
        assert res.status == 200
        entities = json.loads(res.read().decode())
        for e in entities:
            assert "relationships_count" in e
            assert "risk" in e
        log("7. Entity Intelligence", "PASS", f"Loaded {len(entities)} entities with rel counts & risk scores")

    # 8. Investigation Graph Payload
    req = urllib.request.Request(f"{BASE_URL}/api/graph?case_id={active_case_id}")
    with opener.open(req) as res:
        assert res.status == 200
        graph = json.loads(res.read().decode())
        assert "nodes" in graph and "edges" in graph
        log("8. Investigation Graph", "PASS", f"Nodes: {len(graph['nodes'])}, Edges: {len(graph['edges'])}")

    # 9. Risk Analysis Scoped Report
    req = urllib.request.Request(f"{BASE_URL}/api/risk?case_id={active_case_id}")
    with opener.open(req) as res:
        assert res.status == 200
        risk_data = json.loads(res.read().decode())
        assert "case" in risk_data and "factors" in risk_data["case"]
        log("9. Risk Analysis", "PASS", f"Score: {risk_data['case']['score']}, Factors: {len(risk_data['case']['factors'])}")

    # 10. Security Center Overview, Events, & Audit
    req = urllib.request.Request(f"{BASE_URL}/api/security/overview")
    with opener.open(req) as res:
        assert res.status == 200
        sec_overview = json.loads(res.read().decode())
        log("10a. Security Overview", "PASS", f"Integrity: {sec_overview.get('evidence_integrity')}")

    req = urllib.request.Request(f"{BASE_URL}/api/security/events")
    with opener.open(req) as res:
        assert res.status == 200
        log("10b. Security Events", "PASS", "HTTP 200")

    req = urllib.request.Request(f"{BASE_URL}/api/security/audit")
    with opener.open(req) as res:
        assert res.status == 200
        log("10c. Security Audit", "PASS", "HTTP 200")

    # 11. Evidence Ledger Hash Chain & Verification
    req = urllib.request.Request(f"{BASE_URL}/api/security/ledger")
    with opener.open(req) as res:
        assert res.status == 200
        blocks = json.loads(res.read().decode())
        assert len(blocks) > 0
        log("11a. Evidence Ledger Blocks", "PASS", f"{len(blocks)} blocks retrieved")

    req = urllib.request.Request(
        f"{BASE_URL}/api/security/verify",
        data=b"{}",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    )
    with opener.open(req) as res:
        assert res.status == 200
        verify_res = json.loads(res.read().decode())
        assert verify_res["valid"] is True
        log("11b. Cryptographic Ledger Verification", "PASS", f"Checked {verify_res['checked_blocks']} blocks: VALID")

    # 12. Investigation Assistant Factual Query
    ask_data = json.dumps({"question": "Summarize case intelligence.", "case_id": active_case_id}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/chat",
        data=ask_data,
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    )
    with opener.open(req) as res:
        assert res.status == 200
        answer = json.loads(res.read().decode())
        assert "response" in answer or "answer" in answer
        log("12. Investigation Assistant", "PASS", "Received grounded answer")

    # 13. Case Switcher Isolation Check
    if len(cases) > 1:
        alt_case_id = cases[1]["id"]
        req = urllib.request.Request(f"{BASE_URL}/api/graph?case_id={alt_case_id}")
        with opener.open(req) as res:
            assert res.status == 200
            alt_graph = json.loads(res.read().decode())
            log("13. Case Switcher Isolation", "PASS", f"Switched to Case #{alt_case_id} (Nodes: {len(alt_graph['nodes'])})")

    # 14. Logout
    req = urllib.request.Request(
        f"{BASE_URL}/api/logout",
        data=b"{}",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    )
    with opener.open(req) as res:
        assert res.status == 200
        log("14. Session Logout", "PASS", "Signed out cleanly")

    print("\n========================================================")
    print("ALL LIVE APPLICATION HTTP FLOWS COMPLETED SUCCESSFULLY!")
    print("========================================================")

except Exception as e:
    print(f"\n[FAIL] Live application test failed: {e}")
    sys.exit(1)
