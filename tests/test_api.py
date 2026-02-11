import io
import sys
from pathlib import Path
from importlib.machinery import SourceFileLoader

import pytest


ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "Back-end"


def load_backend(tmp_path):
    sys.path.insert(0, str(BACKEND_DIR))
    module = SourceFileLoader("template_backend", str(BACKEND_DIR / "Template-backend.py")).load_module()
    module.DB_PATH = tmp_path / "test.db"
    module.UPLOAD_DIR = tmp_path / "uploads"
    module._db_initialized = False
    module.init_db()
    module.app.config.update(TESTING=True)
    return module


def csrf(client):
    res = client.get("/api/csrf")
    assert res.status_code == 200
    return res.get_json()["token"]


def create_user(module, email="user@example.com", password="User1234", name="User"):
    with module.get_db() as conn:
        conn.execute(
            """
            INSERT INTO users (name, email, password_hash, role, email_verified, active)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, email, module.generate_password_hash(password), "analyst", 1, 1),
        )


def make_admin(module, email="admin@example.com", password="Admin123", name="Admin"):
    with module.get_db() as conn:
        conn.execute(
            """
            INSERT INTO users (name, email, password_hash, role, email_verified, active)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, email, module.generate_password_hash(password), "admin", 1, 1),
        )


@pytest.fixture()
def app_client(tmp_path):
    module = load_backend(tmp_path)
    client = module.app.test_client()
    return module, client


def login(client, token, email, password):
    return client.post(
        "/api/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": token},
    )


def test_signup_and_login(app_client):
    module, client = app_client
    token = csrf(client)
    res = client.post(
        "/api/signup",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "password": "Test1234",
            "confirm_password": "Test1234",
        },
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 200
    # Mark verified
    with module.get_db() as conn:
        conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", ("test@example.com",))
    token = csrf(client)
    login_res = login(client, token, "test@example.com", "Test1234")
    assert login_res.status_code == 200


def test_dashboard_requires_login(app_client):
    _, client = app_client
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/login" in res.headers.get("Location", "")


def test_csv_upload_scoring(app_client):
    module, client = app_client
    create_user(module)
    token = csrf(client)
    assert login(client, token, "user@example.com", "User1234").status_code == 200
    token = csrf(client)
    csv_content = "amount,country,merchant_risk_score,transactions_last_1h\n100,US,0.1,1\n"
    data = {
        "file": (io.BytesIO(csv_content.encode("utf-8")), "sample.csv"),
    }
    res = client.post("/api/upload-csv", data=data, headers={"X-CSRF-Token": token})
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["summary"]["total"] == 1


def test_admin_audit_and_evaluation(app_client):
    module, client = app_client
    make_admin(module)
    token = csrf(client)
    assert login(client, token, "admin@example.com", "Admin123").status_code == 200
    token = csrf(client)
    csv_content = "amount,country,merchant_risk_score,transactions_last_1h,label\n100,US,0.1,1,Normal\n"
    data = {"file": (io.BytesIO(csv_content.encode("utf-8")), "labeled.csv")}
    res = client.post("/api/evaluate-csv", data=data, headers={"X-CSRF-Token": token})
    assert res.status_code == 200
    history = client.get("/api/admin/evaluations")
    assert history.status_code == 200
    items = history.get_json()["items"]
    assert len(items) == 1
    audit = client.get("/api/admin/audit")
    assert audit.status_code == 200
