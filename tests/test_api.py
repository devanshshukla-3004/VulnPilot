import os
os.environ["VULNPILOT_DATABASE_URL"] = "sqlite:///./test_vulnpilot.db"
from fastapi.testclient import TestClient
from backend.app.main import app
client = TestClient(app)

def test_health():
    assert client.get("/api/health").json()["status"] == "ok"

def test_import_and_findings():
    payload = {"assets":[{"asset_key":"TEST-ASSET","hostname":"test-host","environment":"test","criticality":"critical","internet_exposed":True}],
               "vulnerabilities":[{"finding_key":"TEST-FIND","asset_key":"TEST-ASSET","title":"Test finding","cvss":9.0,"exploit_available":True,"status":"open","description":"test fixture"}]}
    result = client.post("/api/import/json", json=payload)
    assert result.status_code == 200
    assert result.json()["findings_added"] == 1
    findings = client.get("/api/findings").json()
    assert any(f["finding_key"] == "TEST-FIND" and f["risk_score"] > 0 for f in findings)

def test_invalid_status_filter():
    assert client.get("/api/findings?status=invalid").status_code == 422
