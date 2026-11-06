import os, tempfile, unittest
from fastapi.testclient import TestClient

# The test process uses a disposable database to avoid touching a developer's data.
fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
os.environ["DATABASE_URL"] = "sqlite:///" + path.replace("\\", "/")
os.environ["DEMO_PASSWORD"] = "test-password"
from app.main import app
client = TestClient(app)

class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        response=client.post("/api/auth/login",json={"username":"admin","password":"test-password"})
        cls.headers={"Authorization":"Bearer "+response.json()["access_token"]}
    def test_health_and_login(self):
        self.assertEqual(client.get("/api/health").status_code,200)
    def test_detection_investigation_and_deduplication(self):
        first=client.post("/api/logs/ingest",headers=self.headers,json={"service":"test-db","level":"ERROR","message":"Database connection failure: exhausted"}).json()
        second=client.post("/api/logs/ingest",headers=self.headers,json={"service":"test-db","level":"ERROR","message":"Database connection failure: timeout"}).json()
        self.assertEqual(first["id"],second["id"])
        self.assertGreaterEqual(second["occurrences"],2)
        detail=client.post("/api/agents/investigate/"+first["id"],headers=self.headers).json()
        self.assertIn("Database",detail["root_cause"])
    def test_recovery_requires_approval_and_is_audited(self):
        incident=client.post("/api/logs/ingest",headers=self.headers,json={"service":"test-worker","level":"HIGH","message":"High CPU usage sustained above 95 percent"}).json()
        url="/api/recovery/execute/"+incident["id"]
        self.assertEqual(client.post(url,headers=self.headers).status_code,409)
        self.assertEqual(client.post("/api/recovery/approve/"+incident["id"],headers=self.headers).status_code,200)
        executed=client.post(url,headers=self.headers).json()
        self.assertTrue(executed["verified"]); self.assertEqual(executed["mode"],"simulation")
        events=client.get("/api/audit",headers=self.headers).json()
        self.assertTrue(any(x["event"]=="RECOVERY_EXECUTED_SIMULATED" for x in events))

if __name__=="__main__": unittest.main()
