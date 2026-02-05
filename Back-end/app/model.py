from __future__ import annotations

from dataclasses import dataclass
import json
from hashlib import md5
from pathlib import Path
from typing import Dict, List, Tuple

try:
  import joblib
except ImportError:  # pragma: no cover
  joblib = None

try:
  import shap
except ImportError:  # pragma: no cover
  shap = None
REQUIRED_FIELDS = {"amount": float}

NUMERIC_FIELDS = {
  "amount": float,
  "account_age_days": float,
  "user_age": float,
  "average_transaction_amount": float,
  "historical_fraud_count": float,
  "transactions_last_1h": float,
  "transactions_last_24h": float,
  "amount_last_24h": float,
  "unique_merchants_last_24h": float,
  "unique_countries_last_7d": float,
  "country_risk_score": float,
  "merchant_risk_score": float,
  "device_risk_score": float,
  "ip_reputation_score": float,
  "hour_of_day": float,
  "day_of_week": float,
}

BOOLEAN_FIELDS = {
  "kyc_verified",
  "proxy_vpn_flag",
  "blacklist_match_flag",
  "billing_shipping_mismatch",
  "country_mismatch",
  "new_device_for_user",
  "new_location_for_user",
  "is_weekend",
  "is_holiday",
}

CATEGORICAL_FIELDS = {
  "currency",
  "transaction_type",
  "channel",
  "country",
  "city",
  "merchant_id",
  "device_id",
  "browser_fingerprint",
}

FEATURE_ORDER = [
  "amount",
  "currency_USD",
  "currency_EUR",
  "currency_INR",
  "transaction_type_POS",
  "transaction_type_ONLINE",
  "transaction_type_TRANSFER",
  "channel_WEB",
  "channel_MOBILE",
  "channel_ATM",
  "country_US",
  "country_IN",
  "city_New York",
  "city_Mumbai",
  "account_age_days",
  "user_age",
  "kyc_verified",
  "average_transaction_amount",
  "historical_fraud_count",
  "transactions_last_1h",
  "transactions_last_24h",
  "amount_last_24h",
  "unique_merchants_last_24h",
  "unique_countries_last_7d",
  "merchant_id",
  "device_id",
  "browser_fingerprint",
  "proxy_vpn_flag",
  "country_risk_score",
  "merchant_risk_score",
  "device_risk_score",
  "ip_reputation_score",
  "blacklist_match_flag",
  "hour_of_day",
  "day_of_week",
  "is_weekend",
  "is_holiday",
  "billing_shipping_mismatch",
  "country_mismatch",
  "new_device_for_user",
  "new_location_for_user",
]

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model"
METADATA_PATH = MODEL_DIR / "model_metadata.json"


@dataclass
class Prediction:
  probability: float
  label: str
  reasons: List[str]


def validate_features(raw: Dict) -> Tuple[Dict, List[str]]:
  cleaned: Dict = {}
  errors: List[str] = []

  for key, expected in REQUIRED_FIELDS.items():
    if key not in raw or raw.get(key) in (None, ""):
      errors.append(f"Missing {key}")
      continue

    value = raw.get(key)
    try:
      if expected is float:
        cleaned[key] = float(value)
      elif expected is int:
        cleaned[key] = int(float(value))
      else:
        cleaned[key] = str(value).strip()
    except (ValueError, TypeError):
      errors.append(f"Invalid {key}")

  for key, expected in NUMERIC_FIELDS.items():
    value = raw.get(key)
    if value in (None, ""):
      continue
    try:
      cleaned[key] = float(value)
    except (ValueError, TypeError):
      errors.append(f"Invalid {key}")

  for key in BOOLEAN_FIELDS:
    value = raw.get(key)
    if value in (None, ""):
      continue
    try:
      cleaned[key] = 1 if str(value).lower() in ("1", "true", "yes") else 0
    except (ValueError, TypeError):
      errors.append(f"Invalid {key}")

  for key in CATEGORICAL_FIELDS:
    value = raw.get(key)
    if value in (None, ""):
      continue
    cleaned[key] = str(value).strip()

  return cleaned, errors


def clean_features(features: Dict) -> Dict:
  cleaned = dict(features)
  if "currency" in cleaned and cleaned["currency"]:
    cleaned["currency"] = str(cleaned["currency"]).upper()
  if "country" in cleaned and cleaned["country"]:
    cleaned["country"] = str(cleaned["country"]).upper()
  if "ip_country" in cleaned and cleaned["ip_country"]:
    cleaned["ip_country"] = str(cleaned["ip_country"]).upper()
  if "city" in cleaned and cleaned["city"]:
    cleaned["city"] = str(cleaned["city"]).title()
  if "transaction_type" in cleaned and cleaned["transaction_type"]:
    cleaned["transaction_type"] = str(cleaned["transaction_type"]).upper()
  if "channel" in cleaned and cleaned["channel"]:
    cleaned["channel"] = str(cleaned["channel"]).upper()
  if "merchant_id" in cleaned and cleaned["merchant_id"]:
    cleaned["merchant_id"] = str(cleaned["merchant_id"]).upper()
  if "device_id" in cleaned and cleaned["device_id"]:
    cleaned["device_id"] = str(cleaned["device_id"]).upper()
  return cleaned


def _hash_category(value: str) -> float:
  digest = md5(value.encode("utf-8")).hexdigest()
  return float(int(digest[:8], 16) % 100000)


def load_metadata() -> Dict:
  if not METADATA_PATH.exists():
    return {}
  try:
    return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
  except (json.JSONDecodeError, OSError):
    return {}


def encode_features_hash(features: Dict) -> Dict:
  encoded = {}
  for name in FEATURE_ORDER:
    if name in CATEGORICAL_FIELDS:
      val = features.get(name, "")
      encoded[name] = _hash_category(str(val)) if val else 0.0
    elif name in BOOLEAN_FIELDS:
      encoded[name] = float(features.get(name, 0))
    else:
      encoded[name] = float(features.get(name, 0))
  return encoded


def encode_features_onehot(features: Dict, metadata: Dict) -> Tuple[List[float], List[str]]:
  vector: List[float] = []
  labels: List[str] = []
  encoders = metadata.get("encoders", {})
  one_hot = encoders.get("one_hot", {})

  def one_hot_value(field: str, option: str) -> float:
    current = str(features.get(field, "")).strip()
    return 1.0 if current == option else 0.0

  def label_encode(field: str) -> float:
    value = str(features.get(field, "")).strip()
    if not value:
      return 0.0
    return _hash_category(value)

  for name in metadata.get("feature_order", FEATURE_ORDER):
    if "_" in name and name.split("_", 1)[0] in one_hot:
      field, option = name.split("_", 1)
      labels.append(name)
      vector.append(one_hot_value(field, option))
    elif name in BOOLEAN_FIELDS:
      labels.append(name)
      vector.append(float(features.get(name, 0)))
    elif name in NUMERIC_FIELDS:
      labels.append(name)
      vector.append(float(features.get(name, 0)))
    elif name in ("merchant_id", "device_id", "browser_fingerprint"):
      labels.append(name)
      vector.append(label_encode(name))
    else:
      labels.append(name)
      vector.append(float(features.get(name, 0)))

  return vector, labels


class PlaceholderFraudModel:
  def predict(self, features: Dict) -> Prediction:
    encoded = encode_features_hash(features)
    amount = float(encoded.get("amount", 0))
    velocity = float(encoded.get("transactions_last_1h", 0))
    country_risk = float(encoded.get("country_risk_score", 0))
    insider = int(float(encoded.get("blacklist_match_flag", 0)))

    score = 0.0
    reasons: List[str] = []
    if amount >= 100000:
      score += 0.4
      reasons.append("High amount")
    if velocity >= 50:
      score += 0.2
      reasons.append("High velocity")
    score += min(0.2, country_risk * 0.2)
    if country_risk >= 0.5:
      reasons.append("Elevated country risk")
    if insider == 1:
      score += 0.3
      reasons.append("Insider flag")

    probability = min(score, 1.0)
    if probability >= 0.7:
      label = "Fraud"
    elif probability >= 0.5:
      label = "Review"
    else:
      label = "Normal"

    if not reasons:
      reasons.append("No high-risk signals")

    return Prediction(probability=probability, label=label, reasons=reasons)


class ModelWrapper:
  def __init__(self, model):
    self.model = model
    self._explainer = None
    self.metadata = load_metadata()

  def _predict_proba(self, features: Dict) -> float:
    features = clean_features(features)
    if self.metadata.get("encoders", {}).get("one_hot"):
      vector, _ = encode_features_onehot(features, self.metadata)
      values = [vector]
    else:
      encoded = encode_features_hash(features)
      values = [[encoded.get(name, 0) for name in FEATURE_ORDER]]
    if hasattr(self.model, "predict_proba"):
      proba = self.model.predict_proba(values)[0]
      return float(proba[-1])
    if hasattr(self.model, "decision_function"):
      score = float(self.model.decision_function(values)[0])
      return 1 / (1 + pow(2.71828, -score))
    prediction = self.model.predict(values)[0]
    try:
      return float(prediction)
    except (ValueError, TypeError):
      return 1.0 if str(prediction).lower() in ("fraud", "1", "true") else 0.0

  def explain(self, features: Dict) -> List[str]:
    reasons: List[str] = []
    features = clean_features(features)
    if self.metadata.get("encoders", {}).get("one_hot"):
      vector, labels = encode_features_onehot(features, self.metadata)
      values = vector
      feature_labels = labels
    else:
      values = [features.get(name, 0) for name in FEATURE_ORDER]
      feature_labels = FEATURE_ORDER
    if shap is not None:
      try:
        if self._explainer is None:
          self._explainer = shap.Explainer(self.model)
        shap_values = self._explainer([values])
        vals = getattr(shap_values, "values", None)
        if vals is not None and len(vals):
          contributions = list(vals[0])
          ranked = sorted(
            zip(feature_labels, values, contributions),
            key=lambda item: abs(item[2]),
            reverse=True,
          )
          for name, value, weight in ranked[:3]:
            reasons.append(f"{name}: {value} (impact {weight:.3f})")
          return reasons
      except Exception:
        pass

    if hasattr(self.model, "feature_importances_"):
      weights = list(self.model.feature_importances_)
    elif hasattr(self.model, "coef_"):
      weights = list(self.model.coef_[0])
    else:
      return PlaceholderFraudModel().predict(features).reasons

    ranked = sorted(
      zip(feature_labels, values, weights), key=lambda item: abs(item[2]), reverse=True
    )
    for name, value, weight in ranked[:3]:
      reasons.append(f"{name}: {value} (weight {weight:.2f})")
    return reasons or ["No explanation available"]

  def predict(self, features: Dict) -> Prediction:
    probability = min(max(self._predict_proba(features), 0.0), 1.0)
    if probability >= 0.7:
      label = "Fraud"
    elif probability >= 0.5:
      label = "Review"
    else:
      label = "Normal"
    reasons = self.explain(features)
    return Prediction(probability=probability, label=label, reasons=reasons)


def load_model() -> Tuple[object, str]:
  if joblib:
    model_path = MODEL_DIR / "model.joblib"
    try:
      if model_path.exists():
        model = joblib.load(str(model_path))
        return ModelWrapper(model), "joblib-model"
    except Exception:
      pass
  return PlaceholderFraudModel(), "placeholder"
