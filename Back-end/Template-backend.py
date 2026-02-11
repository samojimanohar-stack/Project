from __future__ import annotations
from pathlib import Path
from typing import Any, Dict
import csv
import io
import json
import os
import secrets
import sqlite3
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
import re
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from app.model import (
  BOOLEAN_FIELDS,
  CATEGORICAL_FIELDS,
  NUMERIC_FIELDS,
  REQUIRED_FIELDS,
  load_model,
  validate_features,
)
BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / "config" / ".env")
FRONT_DIR = BASE_DIR.parent / "Front-end"
PAGES_DIR = FRONT_DIR / "pages"
CSS_DIR = FRONT_DIR / "css"
JS_DIR = FRONT_DIR / "js"
IMG_DIR = FRONT_DIR / "image"
# Allow overriding database location in deployment environments.
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "db" / "Template-db.db")))
UPLOAD_DIR = BASE_DIR / "uploads"
MODEL, MODEL_SOURCE = load_model()
app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
app.permanent_session_lifetime = timedelta(minutes=30)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
TEST_MODE = os.getenv("TEST_MODE", "").lower() in {"1", "true", "yes"}
DEFAULT_FRAUD_THRESHOLD = float(os.getenv("FRAUD_THRESHOLD", "0.70"))
DEFAULT_REVIEW_THRESHOLD = float(os.getenv("REVIEW_THRESHOLD", "0.50"))


def get_db() -> sqlite3.Connection:
  conn = sqlite3.connect(DB_PATH)
  conn.row_factory = sqlite3.Row
  return conn


def init_db() -> None:
  DB_PATH.parent.mkdir(parents=True, exist_ok=True)
  UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
  with get_db() as conn:
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        active INTEGER NOT NULL DEFAULT 1,
        email_verified INTEGER NOT NULL DEFAULT 0,
        verify_token TEXT,
        verify_expires TEXT,
        reset_token TEXT,
        reset_expires TEXT,
        last_login TEXT,
        login_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
    if "active" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    if "email_verified" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
    if "verify_token" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN verify_token TEXT")
    if "verify_expires" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN verify_expires TEXT")
    if "reset_token" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
    if "reset_expires" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN reset_expires TEXT")
    if "last_login" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    if "login_count" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0")
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS upload_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        summary TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS visual_state (
        user_id INTEGER PRIMARY KEY,
        summary TEXT,
        samples TEXT,
        fields TEXT,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        target_id INTEGER,
        detail TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS evaluation_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        metrics TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    conn.execute(
      """
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )


def bootstrap_admin_user() -> None:
  """
  Ensure the configured admin account exists and is active.
  This helps deployments where seed data is empty or reset.
  """
  if not ADMIN_EMAIL or not ADMIN_PASSWORD:
    return
  password_hash = generate_password_hash(ADMIN_PASSWORD)
  with get_db() as conn:
    row = conn.execute("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
    if row:
      conn.execute(
        """
        UPDATE users
        SET password_hash = ?, role = 'admin', active = 1, email_verified = 1
        WHERE email = ?
        """,
        (password_hash, ADMIN_EMAIL),
      )
    else:
      conn.execute(
        """
        INSERT INTO users (name, email, password_hash, role, active, email_verified)
        VALUES (?, ?, ?, 'admin', 1, 1)
        """,
        ("Admin", ADMIN_EMAIL, password_hash),
      )


_db_initialized = False


@app.before_request
def _startup() -> None:
  global _db_initialized
  if _db_initialized:
    return
  init_db()
  bootstrap_admin_user()
  _db_initialized = True


def now_utc() -> datetime:
  return datetime.utcnow()


def current_user_id() -> int | None:
  return session.get("user_id")


def get_user_role(user_id: int) -> str | None:
  with get_db() as conn:
    row = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
  return row["role"] if row else None


def require_admin(user_id: int) -> bool:
  # Strict mode: admin access is tied to the configured ADMIN_EMAIL only.
  if not ADMIN_EMAIL:
    return False
  if get_user_role(user_id) != "admin":
    return False
  with get_db() as conn:
    row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
  return bool(row) and row["email"].lower() == ADMIN_EMAIL


def log_audit(actor_id: int, action: str, target_id: int | None = None, detail: str | None = None) -> None:
  try:
    with get_db() as conn:
      conn.execute(
        """
        INSERT INTO audit_logs (actor_id, action, target_id, detail)
        VALUES (?, ?, ?, ?)
        """,
        (actor_id, action, target_id, detail),
      )
  except Exception:
    pass


def ensure_csrf() -> str:
  token = session.get("csrf_token")
  if not token:
    token = secrets.token_urlsafe(24)
    session["csrf_token"] = token
  return token


def csrf_required() -> bool:
  return request.method in {"POST", "PUT", "DELETE"} and request.path.startswith("/api/")


@app.before_request
def _csrf_guard() -> None:
  if not csrf_required():
    return
  token = session.get("csrf_token")
  header = request.headers.get("X-CSRF-Token")
  if not token or not header or header != token:
    return jsonify({"status": "error", "message": "CSRF token missing or invalid."}), 403


def password_policy(password: str) -> list[str]:
  errors = []
  if len(password) < 8:
    errors.append("Password must be at least 8 characters.")
  if not any(c.islower() for c in password):
    errors.append("Password must include a lowercase letter.")
  if not any(c.isupper() for c in password):
    errors.append("Password must include an uppercase letter.")
  if not any(c.isdigit() for c in password):
    errors.append("Password must include a number.")
  return errors


def smtp_configured() -> bool:
  if os.getenv("SMTP_DISABLED", "").strip().lower() in {"1", "true", "yes"}:
    return False
  # SMTP_FROM is optional; when omitted we fallback to SMTP_USER.
  return all(os.getenv(key) for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"))


def send_email(to_address: str, subject: str, body: str) -> bool:
  if not smtp_configured():
    return False
  msg = EmailMessage()
  msg["Subject"] = subject
  msg["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER")
  msg["To"] = to_address
  msg.set_content(body)
  host = os.getenv("SMTP_HOST")
  port = int(os.getenv("SMTP_PORT", "587"))
  user = os.getenv("SMTP_USER")
  password = os.getenv("SMTP_PASS")
  timeout = float(os.getenv("SMTP_TIMEOUT", "5"))
  use_ssl = os.getenv("SMTP_USE_SSL", "").strip().lower() in {"1", "true", "yes"}
  use_starttls = os.getenv("SMTP_USE_STARTTLS", "1").strip().lower() in {"1", "true", "yes"}
  try:
    if use_ssl or port == 465:
      smtp_client = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
      smtp_client = smtplib.SMTP(host, port, timeout=timeout)
    with smtp_client as smtp:
      if use_starttls and not use_ssl and port != 465:
        smtp.starttls()
      smtp.login(user, password)
      smtp.send_message(msg)
    return True
  except Exception as exc:
    # Print concise SMTP error for platform logs (Render/PythonAnywhere).
    print(f"[smtp] send failed: {exc}")
    return False


def absolute_url(path: str) -> str:
  configured_base = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
  if configured_base:
    base = configured_base
  else:
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    base = f"{proto}://{host}".rstrip("/")
  return f"{base}{path}"


def _parse_float(value: Any, default: float) -> float:
  try:
    return float(value)
  except (TypeError, ValueError):
    return default


def get_setting(key: str, default: str | None = None) -> str | None:
  with get_db() as conn:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
  if row:
    return row["value"]
  return default


def set_setting(key: str, value: Any) -> None:
  with get_db() as conn:
    conn.execute(
      """
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = datetime('now')
      """,
      (key, str(value)),
    )


def get_thresholds() -> tuple[float, float]:
  fraud = _parse_float(get_setting("fraud_threshold", str(DEFAULT_FRAUD_THRESHOLD)), DEFAULT_FRAUD_THRESHOLD)
  review = _parse_float(get_setting("review_threshold", str(DEFAULT_REVIEW_THRESHOLD)), DEFAULT_REVIEW_THRESHOLD)
  fraud = min(max(fraud, 0.05), 0.99)
  review = min(max(review, 0.01), fraud - 0.01)
  return fraud, review


def label_by_threshold(probability: float) -> str:
  fraud_threshold, review_threshold = get_thresholds()
  if probability >= fraud_threshold:
    return "Fraud"
  if probability >= review_threshold:
    return "Review"
  return "Normal"


def build_top_features(cleaned: Dict[str, Any], reasons: list[str]) -> list[Dict[str, Any]]:
  top: list[Dict[str, Any]] = []
  for reason in reasons[:5]:
    m = re.match(r"^(?P<feature>[^:]+):\s*(?P<value>.*?)\s*\((?P<meta>[^)]*)\)\s*$", str(reason))
    if m:
      top.append(
        {
          "feature": m.group("feature").strip(),
          "value": m.group("value").strip(),
          "detail": m.group("meta").strip(),
        }
      )
    else:
      top.append({"feature": "signal", "value": "", "detail": str(reason)})
  if top:
    return top[:3]

  risk_candidates = [
    "amount",
    "country_risk_score",
    "merchant_risk_score",
    "device_risk_score",
    "ip_reputation_score",
    "transactions_last_1h",
    "historical_fraud_count",
  ]
  scored = []
  for key in risk_candidates:
    if key not in cleaned:
      continue
    try:
      scored.append((key, float(cleaned.get(key, 0))))
    except Exception:
      continue
  for key, value in sorted(scored, key=lambda item: abs(item[1]), reverse=True)[:3]:
    top.append({"feature": key, "value": value, "detail": "high influence candidate"})
  return top


def csv_schema_report(fieldnames: list[str] | None) -> Dict[str, Any]:
  normalized_fields = [normalize_header(h) for h in (fieldnames or []) if h]
  required = sorted(REQUIRED_FIELDS.keys())
  expected = set(REQUIRED_FIELDS.keys()) | set(NUMERIC_FIELDS.keys()) | set(BOOLEAN_FIELDS) | set(CATEGORICAL_FIELDS)
  missing_required = [name for name in required if name not in normalized_fields]
  unknown = [name for name in normalized_fields if name not in expected and name != "label"]
  recognized = [name for name in normalized_fields if name in expected]
  coverage = round((len(set(recognized)) / max(len(expected), 1)) * 100, 2)
  return {
    "required_fields": required,
    "missing_required": missing_required,
    "recognized_feature_count": len(set(recognized)),
    "expected_feature_count": len(expected),
    "coverage_percent": coverage,
    "unknown_fields": unknown[:20],
    "file_fields": normalized_fields,
  }


def normalize_header(name: str) -> str:
  return "_".join(name.strip().lower().replace("/", " ").split())


def parse_pdf_table(text: str) -> tuple[list[Dict[str, str]], list[str], str | None]:
  lines = [line.strip() for line in text.splitlines() if line.strip()]
  if not lines:
    return [], [], "No readable text found in PDF."

  def parse_delimited(header_line: str, delimiter: str, data_lines: list[str]):
    headers = [h.strip().strip('"') for h in header_line.split(delimiter)]
    normalized = [normalize_header(h) for h in headers]
    if "amount" not in normalized:
      return None
    csv_text = "\n".join([delimiter.join(headers)] + data_lines)
    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)
    rows: list[Dict[str, str]] = []
    for row in reader:
      cleaned = {normalize_header(k): v for k, v in row.items() if k}
      rows.append(cleaned)
    return rows, headers

  def parse_fixed_width(header_line: str, data_lines: list[str]):
    headers = [h.strip().strip('"') for h in re.split(r"\s{2,}", header_line)]
    normalized = [normalize_header(h) for h in headers]
    if "amount" not in normalized:
      return None
    rows: list[Dict[str, str]] = []
    for row_line in data_lines:
      values = [v.strip().strip('"') for v in re.split(r"\s{2,}", row_line)]
      row = {headers[i]: values[i] if i < len(values) else "" for i in range(len(headers))}
      cleaned = {normalize_header(k): v for k, v in row.items() if k}
      rows.append(cleaned)
    return rows, headers

  for idx, line in enumerate(lines):
    delimiter = "," if "," in line else "\t" if "\t" in line else "|" if "|" in line else None
    if delimiter:
      data_lines: list[str] = []
      for row_line in lines[idx + 1 :]:
        if delimiter in row_line:
          data_lines.append(row_line)
        elif data_lines:
          break
      if data_lines:
        parsed = parse_delimited(line, delimiter, data_lines)
        if parsed:
          return parsed[0], parsed[1], None
      continue

    if re.search(r"\s{2,}", line):
      data_lines = []
      for row_line in lines[idx + 1 :]:
        if re.search(r"\s{2,}", row_line):
          data_lines.append(row_line)
        elif data_lines:
          break
      if data_lines:
        parsed = parse_fixed_width(line, data_lines)
        if parsed:
          return parsed[0], parsed[1], None

  return [], [], "PDF upload is disabled in this deployment."
@app.get("/")
def index():
  return send_from_directory(PAGES_DIR, "Template-index.html")
@app.get("/signup")
def signup():
  if current_user_id():
    return redirect("/dashboard")
  return send_from_directory(PAGES_DIR, "Template-signup.html")
@app.get("/login")
def login():
  if current_user_id():
    return redirect("/dashboard")
  return send_from_directory(PAGES_DIR, "Template-login.html")
@app.get("/admin")
def admin():
  user_id = current_user_id()
  if not user_id:
    return redirect("/login")
  if not require_admin(user_id):
    return redirect("/dashboard")
  return send_from_directory(PAGES_DIR, "Template-admin.html")
@app.get("/admin/users")
def admin_users_page():
  user_id = current_user_id()
  if not user_id:
    return redirect("/login")
  if not require_admin(user_id):
    return redirect("/dashboard")
  return send_from_directory(PAGES_DIR, "Template-admin-users.html")
@app.get("/forgot")
def forgot():
  return send_from_directory(PAGES_DIR, "Template-forgot.html")
@app.get("/reset")
def reset():
  return send_from_directory(PAGES_DIR, "Template-reset.html")
@app.get("/verify-status")
def verify_status():
  return send_from_directory(PAGES_DIR, "Template-verify.html")
@app.get("/dashboard")
def dashboard():
  if not current_user_id():
    return redirect("/login")
  return send_from_directory(PAGES_DIR, "Template-dashboard.html")
@app.get("/profile")
def profile():
  if not current_user_id():
    return redirect("/login")
  return send_from_directory(PAGES_DIR, "Template-profile.html")
@app.get("/visuals")
def visuals():
  if not current_user_id():
    return redirect("/login")
  return send_from_directory(PAGES_DIR, "Template-visuals.html")
@app.get("/logout")
def logout():
  response = redirect("/login")
  session.clear()
  return response
@app.get("/css/<path:filename>")
def css(filename: str):
  return send_from_directory(CSS_DIR, filename)
@app.get("/js/<path:filename>")
def js(filename: str):
  return send_from_directory(JS_DIR, filename)
@app.get("/image/<path:filename>")
def image(filename: str):
  return send_from_directory(IMG_DIR, filename)
@app.get("/csv/<path:filename>")
def csv_files(filename: str):
  return send_from_directory(FRONT_DIR / "csv", filename)
@app.get("/api/csrf")
def api_csrf():
  return jsonify({"status": "ok", "token": ensure_csrf()})
@app.get("/api/health")
def api_health():
  try:
    with get_db() as conn:
      conn.execute("SELECT 1").fetchone()
    db_ok = True
  except Exception:
    db_ok = False
  return jsonify(
    {
      "status": "ok" if db_ok else "error",
      "db": "ok" if db_ok else "error",
      "model": MODEL_SOURCE,
      "time": datetime.utcnow().isoformat() + "Z",
    }
  )


@app.post("/api/test/create-user")
def api_test_create_user():
  if not TEST_MODE:
    return jsonify({"status": "error", "message": "Test mode disabled."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  email = str(payload.get("email", "")).strip().lower()
  password = str(payload.get("password", "")).strip()
  name = str(payload.get("name", "Test User")).strip() or "Test User"
  role = str(payload.get("role", "analyst")).strip().lower()
  if not email or not password:
    return jsonify({"status": "error", "message": "Email and password required."}), 400
  if role not in {"admin", "analyst"}:
    return jsonify({"status": "error", "message": "Invalid role."}), 400
  with get_db() as conn:
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
      conn.execute(
        """
        UPDATE users
        SET name = ?, password_hash = ?, role = ?, email_verified = 1, active = 1
        WHERE email = ?
        """,
        (name, generate_password_hash(password), role, email),
      )
    else:
      conn.execute(
        """
        INSERT INTO users (name, email, password_hash, role, email_verified, active)
        VALUES (?, ?, ?, ?, 1, 1)
        """,
        (name, email, generate_password_hash(password), role),
      )
  return jsonify({"status": "ok"})


@app.delete("/api/test/delete-user")
def api_test_delete_user():
  if not TEST_MODE:
    return jsonify({"status": "error", "message": "Test mode disabled."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  email = str(payload.get("email", "")).strip().lower()
  if not email:
    return jsonify({"status": "error", "message": "Email required."}), 400
  with get_db() as conn:
    conn.execute("DELETE FROM users WHERE email = ?", (email,))
  return jsonify({"status": "ok"})
@app.get("/api/me")
def api_me():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
  return jsonify({"status": "ok", "user": dict(row) if row else None})
@app.get("/api/profile")
def api_profile():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute(
      "SELECT id, name, email, role, last_login, login_count, created_at FROM users WHERE id = ?",
      (user_id,),
    ).fetchone()
  return jsonify({"status": "ok", "user": dict(row) if row else None})
@app.post("/api/profile")
def api_profile_update():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  name = str(payload.get("name", "")).strip()
  if not name:
    return jsonify({"status": "error", "message": "Name is required."}), 400
  with get_db() as conn:
    conn.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
  log_audit(user_id, "profile_update", user_id, "name")
  return jsonify({"status": "ok", "message": "Profile updated."})
@app.post("/api/change-password")
def api_change_password():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  current_password = str(payload.get("current_password", "")).strip()
  new_password = str(payload.get("new_password", "")).strip()
  if not current_password or not new_password:
    return jsonify({"status": "error", "message": "Current and new password required."}), 400
  policy_errors = password_policy(new_password)
  if policy_errors:
    return jsonify({"status": "error", "message": " ".join(policy_errors)}), 400
  with get_db() as conn:
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], current_password):
      return jsonify({"status": "error", "message": "Current password is incorrect."}), 400
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user_id))
  log_audit(user_id, "password_change", user_id)
  return jsonify({"status": "ok", "message": "Password changed."})
@app.get("/api/admin/users")
def api_admin_users():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    rows = conn.execute(
      """
      SELECT id, name, email, role, active, email_verified, created_at, last_login, login_count
      FROM users
      ORDER BY id ASC
      """
    ).fetchall()
  users = [dict(row) for row in rows]
  return jsonify({"status": "ok", "users": users})
@app.post("/api/admin/role")
def api_admin_role():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  target_id = int(payload.get("user_id", 0) or 0)
  role = str(payload.get("role", "")).strip().lower()
  if not target_id or role not in {"admin", "analyst"}:
    return jsonify({"status": "error", "message": "Invalid user or role."}), 400
  with get_db() as conn:
    current = conn.execute(
      "SELECT role FROM users WHERE id = ?",
      (target_id,),
    ).fetchone()
    if not current:
      return jsonify({"status": "error", "message": "User not found."}), 404
    if current["role"] == "admin" and role != "admin":
      admins = conn.execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
      ).fetchone()
      if admins and admins["total"] <= 1:
        return jsonify({"status": "error", "message": "At least one admin required."}), 400
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, target_id))
  log_audit(user_id, "role_change", target_id, f"role={role}")
  return jsonify({"status": "ok", "message": "Role updated."})


@app.get("/api/admin/user/<int:target_id>")
def api_admin_user(target_id: int):
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    row = conn.execute(
      """
      SELECT id, name, email, role, active, email_verified, created_at
      FROM users WHERE id = ?
      """,
      (target_id,),
    ).fetchone()
  if not row:
    return jsonify({"status": "error", "message": "User not found."}), 404
  return jsonify({"status": "ok", "user": dict(row)})


@app.post("/api/admin/user")
def api_admin_user_update():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  target_id = int(payload.get("user_id", 0) or 0)
  name = str(payload.get("name", "")).strip()
  role = str(payload.get("role", "")).strip().lower()
  active = payload.get("active", None)
  if not target_id:
    return jsonify({"status": "error", "message": "Invalid user."}), 400
  if role and role not in {"admin", "analyst"}:
    return jsonify({"status": "error", "message": "Invalid role."}), 400
  if active is not None and active not in (0, 1, True, False):
    return jsonify({"status": "error", "message": "Invalid active value."}), 400

  with get_db() as conn:
    current = conn.execute(
      "SELECT id, role, active FROM users WHERE id = ?",
      (target_id,),
    ).fetchone()
    if not current:
      return jsonify({"status": "error", "message": "User not found."}), 404
    if current["role"] == "admin" and role == "analyst":
      admins = conn.execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
      ).fetchone()
      if admins and admins["total"] <= 1:
        return jsonify({"status": "error", "message": "At least one admin required."}), 400
    if current["role"] == "admin" and active in (0, False):
      admins = conn.execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND active = 1"
      ).fetchone()
      if admins and admins["total"] <= 1:
        return jsonify({"status": "error", "message": "At least one active admin required."}), 400

    updates = []
    values = []
    if name:
      updates.append("name = ?")
      values.append(name)
    if role:
      updates.append("role = ?")
      values.append(role)
    if active is not None:
      updates.append("active = ?")
      values.append(1 if active in (1, True) else 0)
    if not updates:
      return jsonify({"status": "error", "message": "No changes provided."}), 400
    values.append(target_id)
    conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
  log_audit(user_id, "user_update", target_id, f"fields={','.join([u.split('=')[0].strip() for u in updates])}")
  return jsonify({"status": "ok", "message": "User updated."})


@app.post("/api/admin/user/reset")
def api_admin_user_reset():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  target_id = int(payload.get("user_id", 0) or 0)
  if not target_id:
    return jsonify({"status": "error", "message": "Invalid user."}), 400
  reset_token = secrets.token_urlsafe(24)
  reset_expires = (now_utc() + timedelta(hours=2)).isoformat()
  with get_db() as conn:
    row = conn.execute("SELECT email FROM users WHERE id = ?", (target_id,)).fetchone()
    if not row:
      return jsonify({"status": "error", "message": "User not found."}), 404
    conn.execute(
      "UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?",
      (reset_token, reset_expires, target_id),
    )
  reset_url = absolute_url(f"/reset?token={reset_token}")
  email_sent = send_email(
    row["email"],
    "Reset your Market Fraud Detection password",
    f"Reset your password by visiting:\n{reset_url}\n\nThis link expires in 2 hours.",
  )
  payload = {"status": "ok", "message": "Reset link sent."}
  if not email_sent:
    payload["reset_url"] = reset_url
  log_audit(user_id, "password_reset", target_id)
  return jsonify(payload)


@app.delete("/api/admin/user/<int:target_id>")
def api_admin_user_delete(target_id: int):
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  if target_id == user_id:
    return jsonify({"status": "error", "message": "You cannot delete your own account."}), 400
  with get_db() as conn:
    current = conn.execute(
      "SELECT role FROM users WHERE id = ?",
      (target_id,),
    ).fetchone()
    if not current:
      return jsonify({"status": "error", "message": "User not found."}), 404
    if current["role"] == "admin":
      admins = conn.execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
      ).fetchone()
      if admins and admins["total"] <= 1:
        return jsonify({"status": "error", "message": "At least one admin required."}), 400
    rows = conn.execute(
      "SELECT stored_path FROM upload_history WHERE user_id = ?",
      (target_id,),
    ).fetchall()
    conn.execute("DELETE FROM upload_history WHERE user_id = ?", (target_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
  for row in rows:
    path = Path(row["stored_path"])
    if path.exists():
      try:
        path.unlink()
      except Exception:
        pass
  log_audit(user_id, "user_delete", target_id)
  return jsonify({"status": "ok", "message": "User deleted."})
@app.get("/api/admin/audit")
def api_admin_audit():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    rows = conn.execute(
      """
      SELECT a.id, a.actor_id, u.email as actor_email, a.action, a.target_id, a.detail, a.created_at
      FROM audit_logs a
      LEFT JOIN users u ON u.id = a.actor_id
      ORDER BY a.id DESC
      LIMIT 50
      """
    ).fetchall()
  return jsonify({"status": "ok", "items": [dict(row) for row in rows]})
@app.get("/api/history")
def api_history():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    rows = conn.execute(
      """
      SELECT id, filename, summary, created_at
      FROM upload_history
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 20
      """,
      (user_id,),
    ).fetchall()
  items = []
  for row in rows:
    summary = None
    if row["summary"]:
      try:
        summary = json.loads(row["summary"])
      except Exception:
        summary = None
    items.append(
      {
        "id": row["id"],
        "filename": row["filename"],
        "summary": summary,
        "created_at": row["created_at"],
      }
    )
  return jsonify({"status": "ok", "items": items})
@app.get("/api/download/<int:record_id>")
def api_download(record_id: int):
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute(
      "SELECT stored_path, filename FROM upload_history WHERE id = ? AND user_id = ?",
      (record_id, user_id),
    ).fetchone()
  if not row:
    return jsonify({"status": "error", "message": "File not found."}), 404
  path = Path(row["stored_path"])
  if not path.exists():
    return jsonify({"status": "error", "message": "File missing on server."}), 404
  return send_from_directory(path.parent, path.name, as_attachment=True, download_name=row["filename"])
@app.delete("/api/history/<int:record_id>")
def api_delete_history(record_id: int):
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute(
      "SELECT stored_path FROM upload_history WHERE id = ? AND user_id = ?",
      (record_id, user_id),
    ).fetchone()
    if not row:
      return jsonify({"status": "error", "message": "File not found."}), 404
    conn.execute(
      "DELETE FROM upload_history WHERE id = ? AND user_id = ?",
      (record_id, user_id),
    )
  path = Path(row["stored_path"])
  if path.exists():
    try:
      path.unlink()
    except Exception:
      pass
  return jsonify({"status": "ok", "message": "Deleted."})
@app.post("/api/test-email")
def api_test_email():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  to_address = str(payload.get("to", "")).strip()
  if not to_address:
    return jsonify({"status": "error", "message": "Recipient email required."}), 400
  sent = send_email(
    to_address,
    "SMTP test - Market Fraud Detection",
    "This is a test email from your Market Fraud Detection System.",
  )
  if not sent:
    return jsonify({"status": "error", "message": "SMTP not configured or send failed."}), 500
  return jsonify({"status": "ok", "message": "Test email sent."})


@app.get("/api/admin/model-settings")
def api_admin_model_settings():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  fraud_threshold, review_threshold = get_thresholds()
  return jsonify(
    {
      "status": "ok",
      "settings": {
        "fraud_threshold": fraud_threshold,
        "review_threshold": review_threshold,
      },
    }
  )


@app.post("/api/admin/model-settings")
def api_admin_model_settings_save():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  fraud_threshold = _parse_float(payload.get("fraud_threshold"), DEFAULT_FRAUD_THRESHOLD)
  review_threshold = _parse_float(payload.get("review_threshold"), DEFAULT_REVIEW_THRESHOLD)
  if not (0.05 <= fraud_threshold <= 0.99):
    return jsonify({"status": "error", "message": "fraud_threshold must be between 0.05 and 0.99."}), 400
  if not (0.01 <= review_threshold < fraud_threshold):
    return jsonify({"status": "error", "message": "review_threshold must be >= 0.01 and lower than fraud_threshold."}), 400
  set_setting("fraud_threshold", f"{fraud_threshold:.4f}")
  set_setting("review_threshold", f"{review_threshold:.4f}")
  log_audit(user_id, "model_settings_update", None, f"fraud={fraud_threshold:.4f},review={review_threshold:.4f}")
  return jsonify(
    {
      "status": "ok",
      "message": "Model thresholds updated.",
      "settings": {"fraud_threshold": fraud_threshold, "review_threshold": review_threshold},
    }
  )


def normalize_label(value: str) -> str:
  val = str(value or "").strip().lower()
  if val in {"fraud", "1", "true", "yes"}:
    return "Fraud"
  if val in {"review", "flag", "suspicious"}:
    return "Review"
  return "Normal"


@app.post("/api/evaluate-csv")
def api_evaluate_csv():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  if "file" not in request.files:
    return jsonify({"status": "error", "message": "CSV file missing."}), 400
  file = request.files["file"]
  if not file or not file.filename:
    return jsonify({"status": "error", "message": "CSV file missing."}), 400
  try:
    content = file.read().decode("utf-8-sig")
  except Exception:
    return jsonify({"status": "error", "message": "Unable to read CSV file."}), 400
  reader = csv.DictReader(io.StringIO(content))
  schema = csv_schema_report(reader.fieldnames or [])
  if not reader.fieldnames or "label" not in [normalize_header(h) for h in reader.fieldnames]:
    return jsonify({"status": "error", "message": "CSV must include a 'label' column."}), 400
  if schema["missing_required"]:
    return jsonify(
      {
        "status": "error",
        "message": f"CSV missing required feature columns: {', '.join(schema['missing_required'])}",
        "schema": schema,
      }
    ), 400

  total = 0
  correct = 0
  confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
  for row in reader:
    total += 1
    raw_label = row.get("label") or row.get("Label") or row.get("LABEL")
    true_label = normalize_label(raw_label)
    cleaned, errs = validate_features(row)
    if errs:
      continue
    pred_obj = MODEL.predict(cleaned)
    pred = label_by_threshold(pred_obj.probability)
    pred_label = normalize_label(pred)
    if pred_label == true_label:
      correct += 1
    is_pos = true_label == "Fraud"
    is_pred_pos = pred_label == "Fraud"
    if is_pos and is_pred_pos:
      confusion["TP"] += 1
    elif (not is_pos) and is_pred_pos:
      confusion["FP"] += 1
    elif (not is_pos) and (not is_pred_pos):
      confusion["TN"] += 1
    else:
      confusion["FN"] += 1

  precision = (
    confusion["TP"] / (confusion["TP"] + confusion["FP"])
    if (confusion["TP"] + confusion["FP"]) > 0
    else 0
  )
  recall = (
    confusion["TP"] / (confusion["TP"] + confusion["FN"])
    if (confusion["TP"] + confusion["FN"]) > 0
    else 0
  )
  f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
  accuracy = (correct / total) if total > 0 else 0

  metrics = {
    "total": total,
    "accuracy": round(accuracy, 4),
    "precision": round(precision, 4),
    "recall": round(recall, 4),
    "f1": round(f1, 4),
    "confusion": confusion,
  }

  with get_db() as conn:
    conn.execute(
      """
      INSERT INTO evaluation_history (user_id, filename, metrics)
      VALUES (?, ?, ?)
      """,
      (user_id, file.filename, json.dumps(metrics)),
    )
  log_audit(user_id, "model_evaluation", None, f"file={file.filename}")

  return jsonify({"status": "ok", **metrics, "schema": schema})


@app.get("/api/admin/evaluations")
def api_admin_evaluations():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    rows = conn.execute(
      """
      SELECT id, filename, metrics, created_at
      FROM evaluation_history
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 20
      """,
      (user_id,),
    ).fetchall()
  items = []
  for row in rows:
    try:
      metrics = json.loads(row["metrics"]) if row["metrics"] else None
    except Exception:
      metrics = None
    items.append(
      {
        "id": row["id"],
        "filename": row["filename"],
        "metrics": metrics,
        "created_at": row["created_at"],
      }
    )
  return jsonify({"status": "ok", "items": items})


@app.get("/api/admin/evaluations/<int:eval_id>/download")
def api_admin_evaluation_download(eval_id: int):
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    row = conn.execute(
      """
      SELECT filename, metrics, created_at
      FROM evaluation_history
      WHERE id = ? AND user_id = ?
      """,
      (eval_id, user_id),
    ).fetchone()
  if not row:
    return jsonify({"status": "error", "message": "Evaluation not found."}), 404
  metrics = json.loads(row["metrics"]) if row["metrics"] else {}
  csv_text = "metric,value\n"
  csv_text += f"filename,{row['filename']}\n"
  csv_text += f"created_at,{row['created_at']}\n"
  csv_text += f"total,{metrics.get('total', '')}\n"
  csv_text += f"accuracy,{metrics.get('accuracy', '')}\n"
  csv_text += f"precision,{metrics.get('precision', '')}\n"
  csv_text += f"recall,{metrics.get('recall', '')}\n"
  csv_text += f"f1,{metrics.get('f1', '')}\n"
  conf = metrics.get("confusion", {})
  csv_text += f"confusion_TP,{conf.get('TP', '')}\n"
  csv_text += f"confusion_FP,{conf.get('FP', '')}\n"
  csv_text += f"confusion_TN,{conf.get('TN', '')}\n"
  csv_text += f"confusion_FN,{conf.get('FN', '')}\n"
  return app.response_class(
    csv_text,
    mimetype="text/csv",
    headers={"Content-Disposition": f"attachment; filename=evaluation_{eval_id}.csv"},
  )
@app.post("/api/signup")
def api_signup():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  name = str(payload.get("name", "")).strip()
  email = str(payload.get("email", "")).strip().lower()
  password = str(payload.get("password", "")).strip()
  confirm_password = str(payload.get("confirm_password", "")).strip()
  if not name or not email or not password or not confirm_password:
    return jsonify({"status": "error", "message": "All fields are required."}), 400
  if confirm_password != password:
    return jsonify({"status": "error", "message": "Passwords do not match."}), 400
  policy_errors = password_policy(password)
  if policy_errors:
    return jsonify({"status": "error", "message": " ".join(policy_errors)}), 400
  password_hash = generate_password_hash(password)
  verify_token = secrets.token_urlsafe(24)
  verify_expires = (now_utc() + timedelta(hours=24)).isoformat()
  # If SMTP is not configured (or intentionally disabled), auto-verify
  # to avoid blocking sign-in on free-tier deployments.
  auto_verify = not smtp_configured()
  if auto_verify:
    verify_token = None
    verify_expires = None
  try:
    with get_db() as conn:
      role = "admin" if ADMIN_EMAIL and email == ADMIN_EMAIL else "analyst"
      conn.execute(
        """
        INSERT INTO users (name, email, password_hash, role, verify_token, verify_expires, email_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (name, email, password_hash, role, verify_token, verify_expires, 1 if auto_verify else 0),
      )
  except sqlite3.IntegrityError:
    return jsonify({"status": "error", "message": "Email already registered."}), 400
  if auto_verify:
    return jsonify({"status": "ok", "message": "Account created. You can sign in now."})
  verify_url = absolute_url(f"/verify?token={verify_token}")
  email_sent = send_email(
    email,
    "Verify your Market Fraud Detection account",
    f"Welcome {name},\n\nVerify your email by visiting:\n{verify_url}\n\nIf you did not create this account, ignore this email.",
  )
  payload = {"status": "ok", "message": "Account created. Verify your email."}
  if not email_sent:
    payload["verify_url"] = verify_url
  return jsonify(payload)
@app.post("/api/login")
def api_login():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  email = str(payload.get("email", "")).strip().lower()
  password = str(payload.get("password", "")).strip()
  if not email or not password:
    return jsonify({"status": "error", "message": "Email and password required."}), 400
  with get_db() as conn:
    row = conn.execute(
      "SELECT id, password_hash, email_verified, active, login_count FROM users WHERE email = ?",
      (email,),
    ).fetchone()
  if not row or not check_password_hash(row["password_hash"], password):
    return jsonify({"status": "error", "message": "Invalid credentials."}), 401
  if not row["active"]:
    return jsonify({"status": "error", "message": "Account disabled."}), 403
  if not row["email_verified"]:
    return jsonify({"status": "error", "message": "Verify your email before signing in."}), 403
  with get_db() as conn:
    conn.execute(
      """
      UPDATE users
      SET last_login = datetime('now'),
          login_count = COALESCE(login_count, 0) + 1
      WHERE id = ?
      """,
      (row["id"],),
    )
  session["user_id"] = row["id"]
  session.permanent = True
  return jsonify({"status": "ok", "message": "Signed in"})
@app.post("/api/request-verify")
def api_request_verify():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  email = str(payload.get("email", "")).strip().lower()
  if not email:
    return jsonify({"status": "error", "message": "Email required."}), 400
  verify_token = secrets.token_urlsafe(24)
  verify_expires = (now_utc() + timedelta(hours=24)).isoformat()
  with get_db() as conn:
    conn.execute(
      "UPDATE users SET verify_token = ?, verify_expires = ? WHERE email = ?",
      (verify_token, verify_expires, email),
    )
  verify_url = absolute_url(f"/verify?token={verify_token}")
  email_sent = send_email(
    email,
    "Verify your Market Fraud Detection account",
    f"Verify your email by visiting:\n{verify_url}",
  )
  payload = {"status": "ok", "message": "Verification link sent."}
  if not email_sent:
    payload["verify_url"] = verify_url
  return jsonify(payload)
@app.get("/verify")
def verify():
  token = request.args.get("token", "")
  if not token:
    return redirect("/verify-status?status=invalid")
  with get_db() as conn:
    row = conn.execute(
      "SELECT id, verify_expires FROM users WHERE verify_token = ?",
      (token,),
    ).fetchone()
    if not row:
      return redirect("/verify-status?status=invalid")
    expires = datetime.fromisoformat(row["verify_expires"]) if row["verify_expires"] else None
    if not expires or expires < now_utc():
      return redirect("/verify-status?status=expired")
    conn.execute(
      "UPDATE users SET email_verified = 1, verify_token = NULL, verify_expires = NULL WHERE id = ?",
      (row["id"],),
    )
  return redirect("/verify-status?status=success")
@app.post("/api/request-password-reset")
def api_request_password_reset():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  email = str(payload.get("email", "")).strip().lower()
  if not email:
    return jsonify({"status": "error", "message": "Email required."}), 400
  with get_db() as conn:
    row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
  # Keep a generic success response to avoid leaking account existence.
  if not row:
    return jsonify({"status": "ok", "message": "Password reset link sent."})
  reset_token = secrets.token_urlsafe(24)
  reset_expires = (now_utc() + timedelta(hours=2)).isoformat()
  with get_db() as conn:
    conn.execute(
      "UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?",
      (reset_token, reset_expires, email),
    )
  reset_url = absolute_url(f"/reset?token={reset_token}")
  email_sent = send_email(
    email,
    "Reset your Market Fraud Detection password",
    f"Reset your password by visiting:\n{reset_url}\n\nThis link expires in 2 hours.",
  )
  payload = {"status": "ok", "message": "Password reset link sent."}
  if not email_sent:
    payload["reset_url"] = reset_url
  return jsonify(payload)
@app.post("/api/reset-password")
def api_reset_password():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  token = str(payload.get("token", "")).strip()
  password = str(payload.get("password", "")).strip()
  if not token or not password:
    return jsonify({"status": "error", "message": "Token and password required."}), 400
  policy_errors = password_policy(password)
  if policy_errors:
    return jsonify({"status": "error", "message": " ".join(policy_errors)}), 400
  with get_db() as conn:
    row = conn.execute(
      "SELECT id, reset_expires FROM users WHERE reset_token = ?",
      (token,),
    ).fetchone()
    if not row:
      return jsonify({"status": "error", "message": "Invalid reset token."}), 400
    expires = datetime.fromisoformat(row["reset_expires"]) if row["reset_expires"] else None
    if not expires or expires < now_utc():
      return jsonify({"status": "error", "message": "Reset token expired."}), 400
    conn.execute(
      "UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?",
      (generate_password_hash(password), row["id"]),
    )
  return jsonify({"status": "ok", "message": "Password updated.", "redirect_to": "/login"})
@app.post("/api/predict")
def api_predict():
  if not current_user_id():
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  cleaned, errors = validate_features(payload)
  if errors:
    return jsonify({"status": "error", "message": ", ".join(errors)}), 400
  prediction = MODEL.predict(cleaned)
  top_features = build_top_features(cleaned, prediction.reasons)
  fraud_threshold, review_threshold = get_thresholds()
  return jsonify(
    {
      "status": "ok",
      "probability": prediction.probability,
      "label": label_by_threshold(prediction.probability),
      "reasons": prediction.reasons,
      "top_features": top_features,
      "thresholds": {"fraud": fraud_threshold, "review": review_threshold},
      "model": MODEL_SOURCE,
    }
  )
@app.post("/api/upload-csv")
def api_upload_csv():
  if not current_user_id():
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if "file" not in request.files:
    return jsonify({"status": "error", "message": "CSV file missing."}), 400
  file = request.files["file"]
  if not file or not file.filename:
    return jsonify({"status": "error", "message": "CSV file missing."}), 400
  original_name = file.filename
  safe_name = secure_filename(original_name) or "upload.csv"
  timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
  stored_name = f"{timestamp}_{safe_name}"
  stored_path = UPLOAD_DIR / stored_name
  try:
    file.save(stored_path)
  except Exception:
    return jsonify({"status": "error", "message": "Unable to save CSV file."}), 400
  try:
    content = stored_path.read_text(encoding="utf-8-sig")
  except Exception:
    return jsonify({"status": "error", "message": "Unable to read CSV file."}), 400
  reader = csv.DictReader(io.StringIO(content))
  schema = csv_schema_report(reader.fieldnames or [])
  if schema["missing_required"]:
    return jsonify(
      {
        "status": "error",
        "message": f"CSV missing required feature columns: {', '.join(schema['missing_required'])}",
        "schema": schema,
      }
    ), 400
  total = 0
  scored = 0
  errors = 0
  label_counts = {"Fraud": 0, "Review": 0, "Normal": 0}
  results = []
  fraud_threshold, review_threshold = get_thresholds()
  for index, row in enumerate(reader, start=1):
    total += 1
    cleaned, errs = validate_features(row)
    if errs:
      errors += 1
      results.append({"row": index, "errors": errs})
      continue
    prediction = MODEL.predict(cleaned)
    final_label = label_by_threshold(prediction.probability)
    top_features = build_top_features(cleaned, prediction.reasons)
    scored += 1
    if final_label in label_counts:
      label_counts[final_label] += 1
    results.append(
      {
        "row": index,
        "label": final_label,
        "probability": prediction.probability,
        "reasons": prediction.reasons,
        "top_features": top_features,
      }
    )
    if total >= 1000:
      break
  samples = [r for r in results if "label" in r][:5]
  summary = {
    "total": total,
    "scored": scored,
    "errors": errors,
    "label_counts": label_counts,
    "schema_coverage_percent": schema["coverage_percent"],
  }
  with get_db() as conn:
    conn.execute(
      """
      INSERT INTO upload_history (user_id, filename, stored_path, summary)
      VALUES (?, ?, ?, ?)
      """,
      (current_user_id(), original_name, str(stored_path), json.dumps(summary)),
    )
  return jsonify(
    {
      "status": "ok",
      "summary": summary,
      "samples": samples,
      "fields": reader.fieldnames or [],
      "schema": schema,
      "thresholds": {"fraud": fraud_threshold, "review": review_threshold},
    }
  )


@app.get("/api/visuals/state")
def api_visuals_state():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute(
      "SELECT summary, samples, fields, updated_at FROM visual_state WHERE user_id = ?",
      (user_id,),
    ).fetchone()
  if not row:
    return jsonify({"status": "ok", "state": None})
  try:
    summary = json.loads(row["summary"]) if row["summary"] else None
    samples = json.loads(row["samples"]) if row["samples"] else []
    fields = json.loads(row["fields"]) if row["fields"] else []
  except Exception:
    summary, samples, fields = None, [], []
  return jsonify(
    {
      "status": "ok",
      "state": {
        "summary": summary,
        "samples": samples,
        "fields": fields,
        "updated_at": row["updated_at"],
      },
    }
  )


@app.post("/api/visuals/state")
def api_visuals_state_save():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  summary = payload.get("summary")
  samples = payload.get("samples")
  fields = payload.get("fields")
  with get_db() as conn:
    conn.execute(
      """
      INSERT INTO visual_state (user_id, summary, samples, fields, updated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        summary = excluded.summary,
        samples = excluded.samples,
        fields = excluded.fields,
        updated_at = datetime('now')
      """,
      (
        user_id,
        json.dumps(summary) if summary is not None else None,
        json.dumps(samples) if samples is not None else None,
        json.dumps(fields) if fields is not None else None,
      ),
    )
  return jsonify({"status": "ok"})


@app.post("/api/upload-pdf")
def api_upload_pdf():
  return jsonify({"status": "error", "message": "PDF upload is disabled in this deployment."}), 400
if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
