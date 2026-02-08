const byId = (id) => document.getElementById(id);
let csrfToken = "";
let vizState = { summary: null, samples: [], fields: [] };

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

const readCsvHeader = (file) =>
  new Promise((resolve) => {
    if (!file) {
      resolve([]);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = String(reader.result || "");
        const firstLine = text.split(/\r?\n/)[0] || "";
        const fields = firstLine
          .split(",")
          .map((field) => field.trim().replace(/^"|"$/g, ""))
          .filter(Boolean);
        resolve(fields);
      } catch (err) {
        resolve([]);
      }
    };
    reader.onerror = () => resolve([]);
    reader.readAsText(file);
  });

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
  const miniStatus = byId("csv-mini-status");
  const setMiniStatus = (message, status = "neutral") => {
    if (!miniStatus) return;
    miniStatus.textContent = message;
    miniStatus.classList.remove("helper-success", "helper-error");
    if (status === "success") miniStatus.classList.add("helper-success");
    if (status === "error") miniStatus.classList.add("helper-error");
  };
  const fileInput = form.querySelector("input[type='file']");
  if (fileInput && miniStatus) {
    fileInput.addEventListener("change", () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) {
        setMiniStatus("No file selected.");
        return;
      }
      const isCsv = file.name.toLowerCase().endsWith(".csv");
      const sizeKb = Math.round(file.size / 1024);
      setMiniStatus(
        `${file.name} • ${sizeKb} KB • ${
          isCsv ? "CSV detected" : file.name.toLowerCase().endsWith(".pdf") ? "PDF detected" : "Unsupported file type"
        }`,
        isCsv || file.name.toLowerCase().endsWith(".pdf") ? "success" : "error"
      );
    });
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fileInput = form.querySelector("input[type='file']");
    if (!fileInput || !fileInput.files.length) {
      setStatus("csv-status", "Please select a CSV file.");
      setMiniStatus("No file selected.");
      return;
    }
    const file = fileInput.files[0];
    const lowerName = file.name.toLowerCase();
    const isCsv = lowerName.endsWith(".csv");
    const isPdf = lowerName.endsWith(".pdf");
    if (!isCsv && !isPdf) {
      setStatus("csv-status", "Only CSV or PDF files are supported.");
      const sizeKb = Math.round(file.size / 1024);
      setMiniStatus(`${file.name} • ${sizeKb} KB • Unsupported file type`, "error");
      return;
    }
    const csvFields = isCsv ? await readCsvHeader(file) : [];
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
    formData.append("file", file);
    try {
      if (!csrfToken) await initCsrf();
      const endpoint = isPdf ? "/api/upload-pdf" : "/api/upload-csv";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("csv-status", data.message || "CSV upload failed.");
        const sizeKb = Math.round(file.size / 1024);
        setMiniStatus(
          `${file.name} • ${sizeKb} KB • Error: ${data.message || "Upload failed"}`,
          "error"
        );
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
      const fields = (data.fields && data.fields.length ? data.fields : csvFields) || [];
      updateVisuals(data.summary, data.samples || [], fields);
      await persistVisualsState();
      const sizeKb = Math.round(file.size / 1024);
      setMiniStatus(`${file.name} • ${sizeKb} KB • ${summaryText}`, "success");
      const downloadStatus = byId("download-visuals-status");
      if (downloadStatus) downloadStatus.textContent = "Exports a PNG snapshot of the charts.";
      hasCsvData = true;
      await refreshHistory();
      setStatus("csv-status", "CSV processed successfully.");
    } catch (err) {
      setStatus("csv-status", "CSV upload failed. Try again.");
      const sizeKb = Math.round(file.size / 1024);
      setMiniStatus(`${file.name} • ${sizeKb} KB • Upload failed`, "error");
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
  initVizControls();
});

const updateVisuals = (summary = null, samples = [], fields = []) => {
  vizState = { summary, samples, fields };
  const vizTotal = byId("viz-total");
  const vizErrors = byId("viz-errors");
  const vizFields = byId("viz-fields");
  if (summary) {
    if (vizTotal) vizTotal.textContent = `Total: ${summary.total}`;
    if (vizErrors) vizErrors.textContent = `Errors: ${summary.errors}`;
  }
  if (vizFields) {
    if (fields && fields.length) {
      vizFields.textContent = `Fields: ${fields.slice(0, 6).join(", ")}`;
    } else {
      vizFields.textContent = "Fields: --";
    }
  }

  const bars = document.querySelectorAll(".viz-bar");
  if (bars.length) {
    const errorRate =
      summary && summary.total ? Math.round((summary.errors / summary.total) * 100) : 35;
    const scoredRate =
      summary && summary.total ? Math.round((summary.scored / summary.total) * 100) : 60;
    const totals = [scoredRate, 100 - scoredRate, errorRate, Math.max(15, errorRate + 20)];
    const labels = ["Scored", "Unscored", "Errors", "Alerts"];
    const colors = [
      "linear-gradient(180deg, rgba(95, 210, 168, 0.95), rgba(24, 96, 78, 0.75))",
      "linear-gradient(180deg, rgba(89, 194, 255, 0.85), rgba(24, 70, 120, 0.7))",
      "linear-gradient(180deg, rgba(255, 122, 89, 0.95), rgba(138, 52, 40, 0.75))",
      "linear-gradient(180deg, rgba(255, 214, 102, 0.9), rgba(120, 82, 26, 0.7))",
    ];
    bars.forEach((bar, idx) => {
      const value = totals[idx] ?? 40;
      bar.style.height = `${Math.max(20, Math.min(100, value))}%`;
      bar.style.background = colors[idx] || colors[1];
      bar.dataset.label = labels[idx] || "Metric";
    });
  }

  renderVizChart();
};

const persistVisualsState = async () => {
  if (!vizState.summary) return;
  try {
    if (!csrfToken) await initCsrf();
    await fetch("/api/visuals/state", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify(vizState),
    });
  } catch (err) {
    // ignore persistence errors
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

const initVizControls = () => {
  const selector = byId("viz-type");
  if (!selector) return;
  selector.addEventListener("change", () => {
    renderVizChart();
  });
};

const renderVizChart = () => {
  const svg = byId("viz-chart");
  if (!svg) return;
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const selector = byId("viz-type");
  const type = selector ? selector.value : "line";
  const title = byId("viz-title");
  if (title) {
    title.textContent =
      type === "pie" ? "Risk mix" : type === "histogram" ? "Risk histogram" : "Risk trend";
  }

  const values = getVizValues();
  const legend = byId("viz-legend");
  if (type === "pie") {
    drawPie(svg, values);
    if (legend) {
      legend.innerHTML = `
        <span style="color: var(--viz-safe);">Scored</span>
        <span style="color: var(--viz-alert);">Errors</span>
        <span style="color: var(--viz-muted);">Unscored</span>
      `;
    }
  } else if (type === "histogram") {
    drawHistogram(svg, values);
    if (legend) {
      legend.innerHTML = `
        <span style="color: var(--viz-line);">Volume</span>
        <span style="color: var(--viz-alert);">Fraud threshold</span>
      `;
    }
  } else {
    drawLine(svg, values);
    if (legend) {
      legend.innerHTML = `
        <span style="color: var(--viz-line);">Risk</span>
        <span style="color: var(--viz-alert);">Fraud threshold</span>
      `;
    }
  }
};

const getVizValues = () => {
  const values = [];
  if (vizState.samples && vizState.samples.length) {
    vizState.samples
      .slice(0, 8)
      .forEach((row) => values.push(Math.round((row.probability || 0) * 100)));
  }
  if (!values.length) values.push(42, 58, 36, 64, 51, 72, 45, 60);
  return values;
};

const drawLine = (svg, values) => {
  const ns = "http://www.w3.org/2000/svg";
  const width = 200;
  const height = 120;
  const padding = 10;
  const max = Math.max(...values, 100);
  const min = Math.min(...values, 0);
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i += 1) {
    const y = padding + (i / gridLines) * (height - padding * 2);
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", padding.toString());
    line.setAttribute("x2", (width - padding).toString());
    line.setAttribute("y1", y.toString());
    line.setAttribute("y2", y.toString());
    line.setAttribute("stroke", "var(--viz-grid)");
    line.setAttribute("stroke-width", "1");
    svg.appendChild(line);
  }

  const fraudLevel = 70;
  const fraudY =
    height -
    padding -
    ((fraudLevel - min) / (max - min || 1)) * (height - padding * 2);
  const fraudLine = document.createElementNS(ns, "line");
  fraudLine.setAttribute("x1", padding.toString());
  fraudLine.setAttribute("x2", (width - padding).toString());
  fraudLine.setAttribute("y1", fraudY.toFixed(1));
  fraudLine.setAttribute("y2", fraudY.toFixed(1));
  fraudLine.setAttribute("stroke", "var(--viz-alert)");
  fraudLine.setAttribute("stroke-width", "2");
  fraudLine.setAttribute("stroke-dasharray", "4 4");
  svg.appendChild(fraudLine);

  const fraudLabel = document.createElementNS(ns, "text");
  fraudLabel.setAttribute("x", (width - padding).toString());
  fraudLabel.setAttribute("y", (fraudY - 2).toFixed(1));
  fraudLabel.setAttribute("text-anchor", "end");
  fraudLabel.setAttribute("fill", "var(--viz-alert)");
  fraudLabel.setAttribute("font-size", "7");
  fraudLabel.textContent = "70%";
  svg.appendChild(fraudLabel);
  const points = values.map((val, idx) => {
    const x = padding + (idx / (values.length - 1 || 1)) * (width - padding * 2);
    const normalized = (val - min) / (max - min || 1);
    const y = height - padding - normalized * (height - padding * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const glow = document.createElementNS(ns, "polyline");
  glow.setAttribute("points", points.join(" "));
  glow.setAttribute("fill", "none");
  glow.setAttribute("stroke", "var(--viz-line-glow)");
  glow.setAttribute("stroke-width", "6");
  glow.setAttribute("stroke-linecap", "round");
  glow.setAttribute("stroke-linejoin", "round");
  svg.appendChild(glow);

  const polyline = document.createElementNS(ns, "polyline");
  polyline.setAttribute("points", points.join(" "));
  polyline.setAttribute("fill", "none");
  polyline.setAttribute("stroke", "var(--viz-line)");
  polyline.setAttribute("stroke-width", "2.8");
  polyline.setAttribute("stroke-linecap", "round");
  polyline.setAttribute("stroke-linejoin", "round");
  svg.appendChild(polyline);

  values.forEach((val, idx) => {
    const x = padding + (idx / (values.length - 1 || 1)) * (width - padding * 2);
    const normalized = (val - min) / (max - min || 1);
    const y = height - padding - normalized * (height - padding * 2);
    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("cx", x.toFixed(1));
    circle.setAttribute("cy", y.toFixed(1));
    circle.setAttribute("r", "2.5");
    circle.setAttribute("fill", "#eef6ff");
    svg.appendChild(circle);
  });
};

const drawHistogram = (svg, values) => {
  const ns = "http://www.w3.org/2000/svg";
  const bins = [0, 20, 40, 60, 80, 100];
  const counts = new Array(bins.length - 1).fill(0);
  values.forEach((val) => {
    const idx = Math.min(counts.length - 1, Math.floor(val / 20));
    counts[idx] += 1;
  });
  const max = Math.max(...counts, 1);
  const width = 200;
  const height = 120;
  const barWidth = width / counts.length - 6;
  const fraudThreshold = 70;
  const fraudY = height - 6 - (fraudThreshold / 100) * (height - 20);
  const fraudLine = document.createElementNS(ns, "line");
  fraudLine.setAttribute("x1", "6");
  fraudLine.setAttribute("x2", (width - 6).toString());
  fraudLine.setAttribute("y1", fraudY.toFixed(1));
  fraudLine.setAttribute("y2", fraudY.toFixed(1));
  fraudLine.setAttribute("stroke", "var(--viz-alert)");
  fraudLine.setAttribute("stroke-width", "2");
  fraudLine.setAttribute("stroke-dasharray", "4 4");
  svg.appendChild(fraudLine);
  counts.forEach((count, idx) => {
    const barHeight = (count / max) * (height - 20);
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", (idx * (barWidth + 6) + 4).toString());
    rect.setAttribute("y", (height - barHeight - 6).toString());
    rect.setAttribute("width", barWidth.toString());
    rect.setAttribute("height", barHeight.toString());
    rect.setAttribute("rx", "6");
    const isHigh = idx >= 3;
    rect.setAttribute("fill", isHigh ? "var(--viz-alert)" : "var(--viz-line)");
    svg.appendChild(rect);
  });
};

const drawPie = (svg, values) => {
  const ns = "http://www.w3.org/2000/svg";
  const summary = vizState.summary;
  const base = summary && summary.total
    ? [
        Math.max(summary.scored - summary.errors, 0),
        summary.errors,
        Math.max(summary.total - summary.scored, 0),
      ]
    : [55, 25, 20];
  const total = base.reduce((sum, val) => sum + val, 0) || 1;
  const colors = [
    "var(--viz-safe)",
    "var(--viz-alert)",
    "var(--viz-muted)",
  ];
  const cx = 100;
  const cy = 60;
  const r = 42;
  let start = -Math.PI / 2;

  base.forEach((val, idx) => {
    const slice = (val / total) * Math.PI * 2;
    const end = start + slice;
    const x1 = cx + r * Math.cos(start);
    const y1 = cy + r * Math.sin(start);
    const x2 = cx + r * Math.cos(end);
    const y2 = cy + r * Math.sin(end);
    const largeArc = slice > Math.PI ? 1 : 0;
    const path = document.createElementNS(ns, "path");
    const d = [
      `M ${cx} ${cy}`,
      `L ${x1} ${y1}`,
      `A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`,
      "Z",
    ].join(" ");
    path.setAttribute("d", d);
    path.setAttribute("fill", colors[idx]);
    svg.appendChild(path);
    start = end;
  });

  const ring = document.createElementNS(ns, "circle");
  ring.setAttribute("cx", cx.toString());
  ring.setAttribute("cy", cy.toString());
  ring.setAttribute("r", "20");
  ring.setAttribute("fill", "rgba(10, 15, 24, 0.9)");
  svg.appendChild(ring);
};


