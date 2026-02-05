const byId = (id) => document.getElementById(id);
const setStatus = (id, message) => {
  const el = byId(id);
  if (el) el.textContent = message;
};
const handlePrediction = () => {
  const form = byId("predict-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("predict-status", "Scoring transaction...");
    try {
      const res = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("predict-status", data.message || "Prediction failed.");
        return;
      }
      const out = byId("predict-output");
      if (out) {
        const risk = data.risk ?? "--";
        const confidence = data.confidence ?? "--";
        out.textContent = `Risk: ${risk} (${confidence}%)`;
      }
      setStatus("predict-status", data.reasons?.join(" | ") || "Scored successfully.");
    } catch (err) {
      setStatus("predict-status", "Prediction failed. Try again.");
    }
  });
};
document.addEventListener("DOMContentLoaded", () => {
  handlePrediction();
});
