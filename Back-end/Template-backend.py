from __future__ import annotations
from pathlib import Path
from typing import Any, Dict
from flask import Flask, jsonify, request, send_from_directory
from app.model import load_model, validate_features
BASE_DIR = Path(__file__).parent
FRONT_DIR = BASE_DIR.parent / "Front-end"
PAGES_DIR = FRONT_DIR / "pages"
CSS_DIR = FRONT_DIR / "css"
JS_DIR = FRONT_DIR / "js"
MODEL, MODEL_SOURCE = load_model()
app = Flask(__name__, static_folder=None)
@app.get("/")
def index():
  return send_from_directory(PAGES_DIR, "Template-index.html")
@app.get("/signup")
def signup():
  return send_from_directory(PAGES_DIR, "Template-signup.html")
@app.get("/login")
def login():
  return send_from_directory(PAGES_DIR, "Template-login.html")
@app.get("/dashboard")
def dashboard():
  return send_from_directory(PAGES_DIR, "Template-dashboard.html")
@app.get("/css/<path:filename>")
def css(filename: str):
  return send_from_directory(CSS_DIR, filename)
@app.get("/js/<path:filename>")
def js(filename: str):
  return send_from_directory(JS_DIR, filename)
@app.post("/api/signup")
def api_signup():
  return jsonify({"status": "ok", "message": "Account created"})
@app.post("/api/login")
def api_login():
  return jsonify({"status": "ok", "message": "Signed in"})
@app.post("/api/predict")
def api_predict():
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
if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
