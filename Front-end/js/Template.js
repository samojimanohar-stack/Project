const byId = (id) => document.getElementById(id);
let csrfToken = "";

const initCsrf = async () => {
  try {
    const res = await fetch("/api/csrf");
    const data = await res.json();
    if (res.ok) csrfToken = data.token;
  } catch (err) {
    csrfToken = "";
  }
};
const setStatus = (id, message) => {
  const el = byId(id);
  if (el) el.textContent = message;
};
let hasCsvData = false;

const handlePrediction = () => {
  const form = byId("predict-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("predict-status", "Scoring transaction...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("predict-status", data.message || "Prediction failed.");
        return;
      }
      const out = byId("predict-output");
      if (out) {
        const label = data.label ?? "--";
        const probability = Math.round((data.probability ?? 0) * 100);
        out.textContent = `Risk: ${label} (${probability}%)`;
      }
      setStatus("predict-status", data.reasons?.join(" | ") || "Scored successfully.");
    } catch (err) {
      setStatus("predict-status", "Prediction failed. Try again.");
    }
  });
};

const handleCsvUpload = () => {
  const form = byId("csv-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fileInput = form.querySelector("input[type='file']");
    if (!fileInput || !fileInput.files.length) {
      setStatus("csv-status", "Please select a CSV file.");
      return;
    }
    setStatus("csv-status", "Uploading and scoring...");
    const summary = byId("csv-summary");
    const sample = byId("csv-sample");
    if (summary) {
      summary.textContent = "";
      summary.classList.remove("show");
    }
    if (sample) {
      sample.textContent = "";
      sample.classList.remove("show");
    }
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/upload-csv", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("csv-status", data.message || "CSV upload failed.");
        return;
      }
      const summaryText = `Rows: ${data.summary.total} | Scored: ${data.summary.scored} | Errors: ${data.summary.errors}`;
      if (summary) {
        summary.textContent = summaryText;
        summary.classList.add("show");
      }
      if (sample && data.samples && data.samples.length) {
        const lines = data.samples.map(
          (row) => `Row ${row.row}: ${row.label} (${Math.round(row.probability * 100)}%)`
        );
        sample.textContent = lines.join(" | ");
        sample.classList.add("show");
      }
      updateVisuals(data.summary, data.samples || []);
      const downloadStatus = byId("download-visuals-status");
      if (downloadStatus) downloadStatus.textContent = "Exports a PNG snapshot of the charts.";
      hasCsvData = true;
      await refreshHistory();
      setStatus("csv-status", "CSV processed successfully.");
    } catch (err) {
      setStatus("csv-status", "CSV upload failed. Try again.");
    }
  });
};
document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  handlePrediction();
  handleCsvUpload();
  handleVisualDownload();
  refreshHistory();
  updateVisuals();
});

const updateVisuals = (summary = null, samples = []) => {
  const vizTotal = byId("viz-total");
  const vizErrors = byId("viz-errors");
  if (summary) {
    if (vizTotal) vizTotal.textContent = `Total: ${summary.total}`;
    if (vizErrors) vizErrors.textContent = `Errors: ${summary.errors}`;
  }

  const line = byId("viz-trend-line");
  const points = [];
  const values = [];
  if (samples.length) {
    samples.slice(0, 5).forEach((row) => values.push(Math.round((row.probability || 0) * 100)));
  } else {
    values.push(40, 55, 45, 65, 50);
  }
  const max = Math.max(...values, 100);
  const min = Math.min(...values, 0);
  values.forEach((val, idx) => {
    const x = (idx / (values.length - 1 || 1)) * 100;
    const normalized = (val - min) / (max - min || 1);
    const y = 35 - normalized * 30;
    points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  });
  if (line) line.setAttribute("points", points.join(" "));

  const bars = document.querySelectorAll(".viz-bar");
  if (bars.length) {
    const errorRate =
      summary && summary.total ? Math.round((summary.errors / summary.total) * 100) : 35;
    const scoredRate =
      summary && summary.total ? Math.round((summary.scored / summary.total) * 100) : 60;
    const totals = [scoredRate, 100 - scoredRate, errorRate, Math.max(15, errorRate + 20)];
    bars.forEach((bar, idx) => {
      const value = totals[idx] ?? 40;
      bar.style.height = `${Math.max(20, Math.min(100, value))}%`;
    });
  }
};

const refreshHistory = async () => {
  const list = byId("history-list");
  const empty = byId("history-empty");
  if (!list || !empty) return;
  list.innerHTML = "";
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    if (!res.ok || !data.items || !data.items.length) {
      empty.style.display = "block";
      hasCsvData = false;
      return;
    }
    empty.style.display = "none";
    hasCsvData = true;
    data.items.forEach((item) => {
      const wrapper = document.createElement("div");
      wrapper.className = "history-item";
      const created = new Date(item.created_at + "Z");
      const stamp = Number.isNaN(created.getTime())
        ? item.created_at
        : created.toLocaleString();
      const summary = item.summary
        ? `Rows: ${item.summary.total} | Scored: ${item.summary.scored} | Errors: ${item.summary.errors}`
        : "Summary unavailable.";
      wrapper.innerHTML = `
        <div class="history-meta">
          <div class="history-title">${item.filename}</div>
          <div class="history-sub">${stamp}</div>
          <div class="history-sub">${summary}</div>
        </div>
        <div class="history-actions">
          <a class="btn btn-ghost" href="/api/download/${item.id}">Download</a>
          <button class="btn btn-ghost history-delete" data-id="${item.id}">Delete</button>
        </div>
      `;
      list.appendChild(wrapper);
    });
    list.querySelectorAll(".history-delete").forEach((button) => {
      button.addEventListener("click", async () => {
        const recordId = button.getAttribute("data-id");
        if (!recordId) return;
        if (!csrfToken) await initCsrf();
        await fetch(`/api/history/${recordId}`, {
          method: "DELETE",
          headers: { "X-CSRF-Token": csrfToken },
        });
        refreshHistory();
      });
    });
  } catch (err) {
    empty.style.display = "block";
    hasCsvData = false;
  }
};

const hydrateAdminLink = async () => {
  const link = byId("admin-link");
  if (!link) return;
  try {
    const res = await fetch("/api/me");
    const data = await res.json();
    if (res.ok && data.user && data.user.role === "admin") {
      link.style.display = "inline-flex";
    }
  } catch (err) {
    link.style.display = "none";
  }
};

const handleVisualDownload = () => {
  const button = byId("download-visuals");
  if (!button) return;
  button.addEventListener("click", () => {
    const downloadStatus = byId("download-visuals-status");
    if (!hasCsvData) {
      if (downloadStatus) {
        downloadStatus.textContent = "Upload a CSV to enable download.";
      }
      return;
    }
    const summary = byId("csv-summary")?.textContent?.trim() || "Summary: --";
    const sample = byId("csv-sample")?.textContent?.trim() || "Samples: --";
    const width = 900;
    const height = 520;
    const scale = window.devicePixelRatio || 1;
    const canvas = document.createElement("canvas");
    canvas.width = width * scale;
    canvas.height = height * scale;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(scale, scale);

    ctx.fillStyle = "#0a0f18";
    ctx.fillRect(0, 0, width, height);

    const gradient = ctx.createLinearGradient(0, 0, width, height);
    gradient.addColorStop(0, "rgba(40, 70, 140, 0.35)");
    gradient.addColorStop(1, "rgba(10, 15, 24, 0.9)");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, width, height);

    ctx.fillStyle = "#e7eefc";
    ctx.font = "600 22px 'DM Sans', sans-serif";
    ctx.fillText("Market Fraud Detection - Visual Snapshot", 32, 42);
    ctx.font = "400 13px 'DM Sans', sans-serif";
    ctx.fillStyle = "rgba(214, 226, 248, 0.7)";
    ctx.fillText(summary, 32, 68);
    ctx.fillText(sample, 32, 88);

    const cardWidth = 400;
    const cardHeight = 160;
    const cardRadius = 16;
    const drawCard = (x, y) => {
      ctx.fillStyle = "rgba(9, 15, 26, 0.8)";
      ctx.strokeStyle = "rgba(70, 140, 255, 0.2)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x + cardRadius, y);
      ctx.arcTo(x + cardWidth, y, x + cardWidth, y + cardHeight, cardRadius);
      ctx.arcTo(x + cardWidth, y + cardHeight, x, y + cardHeight, cardRadius);
      ctx.arcTo(x, y + cardHeight, x, y, cardRadius);
      ctx.arcTo(x, y, x + cardWidth, y, cardRadius);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    };

    drawCard(32, 120);
    drawCard(468, 120);

    ctx.fillStyle = "rgba(214, 226, 248, 0.7)";
    ctx.font = "600 12px 'DM Sans', sans-serif";
    ctx.fillText("RISK TREND", 52, 148);
    ctx.fillText("ALERTS MIX", 488, 148);

    ctx.strokeStyle = "rgba(120, 190, 255, 0.7)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(52, 240);
    ctx.lineTo(120, 220);
    ctx.lineTo(190, 232);
    ctx.lineTo(260, 200);
    ctx.lineTo(330, 218);
    ctx.lineTo(400, 186);
    ctx.stroke();

    const bars = [70, 110, 90, 130];
    bars.forEach((h, i) => {
      const x = 500 + i * 70;
      const y = 260 - h;
      ctx.fillStyle = "rgba(90, 170, 255, 0.8)";
      ctx.fillRect(x, y, 36, h);
    });

    const link = document.createElement("a");
    link.download = "fraud-visuals.png";
    link.href = canvas.toDataURL("image/png");
    link.click();
  });
};


