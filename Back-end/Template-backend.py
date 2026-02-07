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
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from app.model import load_model, validate_features
BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / "config" / ".env")
FRONT_DIR = BASE_DIR.parent / "Front-end"
PAGES_DIR = FRONT_DIR / "pages"
CSS_DIR = FRONT_DIR / "css"
JS_DIR = FRONT_DIR / "js"
IMG_DIR = FRONT_DIR / "image"
DB_PATH = BASE_DIR / "db" / "Template-db.db"
UPLOAD_DIR = BASE_DIR / "uploads"
MODEL, MODEL_SOURCE = load_model()
app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
app.permanent_session_lifetime = timedelta(minutes=30)


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
        email_verified INTEGER NOT NULL DEFAULT 0,
        verify_token TEXT,
        verify_expires TEXT,
        reset_token TEXT,
        reset_expires TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
      """
    )
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in cols:
      conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
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


_db_initialized = False


@app.before_request
def _startup() -> None:
  global _db_initialized
  if _db_initialized:
    return
  init_db()
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
  return get_user_role(user_id) == "admin"


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
  return all(
    os.getenv(key)
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM")
  )


def send_email(to_address: str, subject: str, body: str) -> bool:
  if not smtp_configured():
    return False
  msg = EmailMessage()
  msg["Subject"] = subject
  msg["From"] = os.getenv("SMTP_FROM")
  msg["To"] = to_address
  msg.set_content(body)
  host = os.getenv("SMTP_HOST")
  port = int(os.getenv("SMTP_PORT", "587"))
  user = os.getenv("SMTP_USER")
  password = os.getenv("SMTP_PASS")
  try:
    with smtplib.SMTP(host, port) as smtp:
      smtp.starttls()
      smtp.login(user, password)
      smtp.send_message(msg)
    return True
  except Exception:
    return False


def absolute_url(path: str) -> str:
  base = request.host_url.rstrip("/")
  return f"{base}{path}"
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
@app.get("/api/me")
def api_me():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  with get_db() as conn:
    row = conn.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
  return jsonify({"status": "ok", "user": dict(row) if row else None})
@app.get("/api/admin/users")
def api_admin_users():
  user_id = current_user_id()
  if not user_id:
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  if not require_admin(user_id):
    return jsonify({"status": "error", "message": "Admin role required."}), 403
  with get_db() as conn:
    rows = conn.execute(
      "SELECT id, name, email, role, email_verified, created_at FROM users ORDER BY id ASC"
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
  return jsonify({"status": "ok", "message": "Role updated."})
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
@app.post("/api/signup")
def api_signup():
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  name = str(payload.get("name", "")).strip()
  email = str(payload.get("email", "")).strip().lower()
  password = str(payload.get("password", "")).strip()
  if not name or not email or not password:
    return jsonify({"status": "error", "message": "All fields are required."}), 400
  policy_errors = password_policy(password)
  if policy_errors:
    return jsonify({"status": "error", "message": " ".join(policy_errors)}), 400
  password_hash = generate_password_hash(password)
  verify_token = secrets.token_urlsafe(24)
  verify_expires = (now_utc() + timedelta(hours=24)).isoformat()
  try:
    with get_db() as conn:
      count = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
      role = "admin" if count == 0 else "analyst"
      conn.execute(
        """
        INSERT INTO users (name, email, password_hash, role, verify_token, verify_expires)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, email, password_hash, role, verify_token, verify_expires),
      )
  except sqlite3.IntegrityError:
    return jsonify({"status": "error", "message": "Email already registered."}), 400
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
      "SELECT id, password_hash, email_verified FROM users WHERE email = ?",
      (email,),
    ).fetchone()
  if not row or not check_password_hash(row["password_hash"], password):
    return jsonify({"status": "error", "message": "Invalid credentials."}), 401
  if not row["email_verified"]:
    return jsonify({"status": "error", "message": "Verify your email before signing in."}), 403
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
  return jsonify({"status": "ok", "message": "Password updated."})
@app.post("/api/predict")
def api_predict():
  if not current_user_id():
    return jsonify({"status": "error", "message": "Authentication required."}), 401
  payload: Dict[str, Any] = request.get_json(silent=True) or {}
  cleaned, errors = validate_features(payload)
  if errors:
    return jsonify({"status": "error", "message": ", ".join(errors)}), 400
  prediction = MODEL.predict(cleaned)
  return jsonify(
    {
      "status": "ok",
      "probability": prediction.probability,
      "label": prediction.label,
      "reasons": prediction.reasons,
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
  total = 0
  scored = 0
  errors = 0
  results = []
  for index, row in enumerate(reader, start=1):
    total += 1
    cleaned, errs = validate_features(row)
    if errs:
      errors += 1
      results.append({"row": index, "errors": errs})
      continue
    prediction = MODEL.predict(cleaned)
    scored += 1
    results.append(
      {
        "row": index,
        "label": prediction.label,
        "probability": prediction.probability,
        "reasons": prediction.reasons,
      }
    )
    if total >= 1000:
      break
  samples = [r for r in results if "label" in r][:5]
  summary = {"total": total, "scored": scored, "errors": errors}
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
    }
  )
if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
