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

const loadUsers = async () => {
  const table = byId("admin-table");
  const status = byId("admin-status");
  if (!table || !status) return;
  table.innerHTML = "";
  status.textContent = "Loading users...";
  try {
    const res = await fetch("/api/admin/users");
    const data = await res.json();
    if (!res.ok) {
      status.textContent = data.message || "Unable to load users.";
      return;
    }
    if (!data.users || !data.users.length) {
      status.textContent = "No users found.";
      return;
    }
    status.textContent = "";
    data.users.forEach((user) => {
      const row = document.createElement("div");
      row.className = "admin-row admin-row-role";
      const isNew = !user.login_count || user.login_count < 2;
      row.innerHTML = `
        <div>${user.name}</div>
        <div class="muted">${user.email}</div>
        <div class="admin-badge">${user.role}</div>
        <div class="muted">${user.active ? "Active" : "Disabled"}</div>
        <div class="muted">${isNew ? "New" : "Returning"}</div>
        <div class="muted">${user.email_verified ? "Verified" : "Unverified"}</div>
        <div>
          <select class="field-role" data-id="${user.id}">
            <option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
            <option value="analyst" ${user.role === "analyst" ? "selected" : ""}>Analyst</option>
          </select>
        </div>
      `;
      table.appendChild(row);
    });
    table.querySelectorAll(".field-role").forEach((select) => {
      select.addEventListener("change", async () => {
        const userId = select.getAttribute("data-id");
        if (!userId) return;
        if (!csrfToken) await initCsrf();
        const res = await fetch("/api/admin/role", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
          body: JSON.stringify({ user_id: Number(userId), role: select.value }),
        });
        const data = await res.json();
        if (!res.ok) {
          status.textContent = data.message || "Role update failed.";
          loadUsers();
        } else {
          status.textContent = "Role updated.";
        }
      });
    });
  } catch (err) {
    status.textContent = "Unable to load users.";
  }
};

const loadHealth = async () => {
  const box = byId("admin-health");
  if (!box) return;
  box.textContent = "Checking...";
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    if (!res.ok) {
      box.textContent = "Health check failed.";
      return;
    }
    box.innerHTML = `
      <div class="admin-health-card">
        <div>Database: ${data.db}</div>
        <div>Model: ${data.model}</div>
        <div class="muted">Checked: ${data.time}</div>
      </div>
    `;
  } catch (err) {
    box.textContent = "Health check failed.";
  }
};

const loadModelSettings = async () => {
  const status = byId("model-settings-status");
  const fraudInput = byId("fraud-threshold");
  const reviewInput = byId("review-threshold");
  if (!status || !fraudInput || !reviewInput) return;
  status.textContent = "Loading settings...";
  try {
    const res = await fetch("/api/admin/model-settings");
    const data = await res.json();
    if (!res.ok) {
      status.textContent = data.message || "Unable to load settings.";
      return;
    }
    const settings = data.settings || {};
    fraudInput.value = settings.fraud_threshold ?? 0.7;
    reviewInput.value = settings.review_threshold ?? 0.5;
    status.textContent = "Settings loaded.";
  } catch (err) {
    status.textContent = "Unable to load settings.";
  }
};

const initModelSettings = () => {
  const form = byId("model-settings-form");
  const status = byId("model-settings-status");
  const fraudInput = byId("fraud-threshold");
  const reviewInput = byId("review-threshold");
  if (!form || !status || !fraudInput || !reviewInput) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fraud = Number(fraudInput.value);
    const review = Number(reviewInput.value);
    if (!(fraud >= 0.05 && fraud <= 0.99)) {
      status.textContent = "Fraud threshold must be between 0.05 and 0.99.";
      return;
    }
    if (!(review >= 0.01 && review < fraud)) {
      status.textContent = "Review threshold must be >= 0.01 and lower than fraud threshold.";
      return;
    }
    status.textContent = "Saving settings...";
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/admin/model-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ fraud_threshold: fraud, review_threshold: review }),
      });
      const data = await res.json();
      if (!res.ok) {
        status.textContent = data.message || "Unable to save settings.";
        return;
      }
      status.textContent = "Thresholds saved.";
      await loadModelSettings();
      await loadAudit();
    } catch (err) {
      status.textContent = "Unable to save settings.";
    }
  });
};

const loadAudit = async () => {
  const log = byId("admin-log");
  const status = byId("admin-log-status");
  if (!log || !status) return;
  log.innerHTML = "";
  status.textContent = "Loading audit log...";
  try {
    const res = await fetch("/api/admin/audit");
    const data = await res.json();
    if (!res.ok) {
      status.textContent = data.message || "Unable to load audit log.";
      return;
    }
    if (!data.items || !data.items.length) {
      status.textContent = "No audit events yet.";
      return;
    }
    status.textContent = "";
    data.items.forEach((item) => {
      const row = document.createElement("div");
      row.className = "admin-log-item";
      row.innerHTML = `
        <div>${item.action}</div>
        <div class="muted">Actor: ${item.actor_email || "unknown"} | Target: ${item.target_id || "-"}</div>
        <div class="muted">${item.detail || ""}</div>
        <div class="muted">${item.created_at}</div>
      `;
      log.appendChild(row);
    });
  } catch (err) {
    status.textContent = "Unable to load audit log.";
  }
};

const initEvaluation = () => {
  const form = byId("eval-form");
  const status = byId("eval-status");
  const result = byId("eval-result");
  const history = byId("eval-history");
  const historyStatus = byId("eval-history-status");
  if (!form || !status || !result) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fileInput = byId("eval-file");
    if (!fileInput || !fileInput.files.length) {
      status.textContent = "Please select a CSV file.";
      return;
    }
    status.textContent = "Evaluating...";
    result.innerHTML = "";
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/evaluate-csv", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        status.textContent = data.message || "Evaluation failed.";
        return;
      }
      status.textContent = "Evaluation complete.";
      result.innerHTML = `
        <div class="admin-log-item">Accuracy: ${data.accuracy}</div>
        <div class="admin-log-item">Precision: ${data.precision}</div>
        <div class="admin-log-item">Recall: ${data.recall}</div>
        <div class="admin-log-item">F1: ${data.f1}</div>
        <div class="admin-log-item">Confusion: TP ${data.confusion.TP}, FP ${data.confusion.FP}, TN ${data.confusion.TN}, FN ${data.confusion.FN}</div>
      `;
      loadEvaluationHistory();
    } catch (err) {
      status.textContent = "Evaluation failed.";
    }
  });
};

const loadEvaluationHistory = async () => {
  const history = byId("eval-history");
  const status = byId("eval-history-status");
  if (!history || !status) return;
  history.innerHTML = "";
  status.textContent = "Loading evaluation history...";
  try {
    const res = await fetch("/api/admin/evaluations");
    const data = await res.json();
    if (!res.ok) {
      status.textContent = data.message || "Unable to load evaluation history.";
      return;
    }
    if (!data.items || !data.items.length) {
      status.textContent = "No evaluations yet.";
      return;
    }
    status.textContent = "";
    data.items.forEach((item) => {
      const row = document.createElement("div");
      row.className = "admin-log-item";
      const metrics = item.metrics || {};
      row.innerHTML = `
        <div>${item.filename}</div>
        <div class="muted">Accuracy ${metrics.accuracy ?? "--"} | F1 ${metrics.f1 ?? "--"} | Total ${metrics.total ?? "--"}</div>
        <div class="muted">${item.created_at}</div>
        <div><a class="btn btn-ghost" href="/api/admin/evaluations/${item.id}/download">Download report</a></div>
      `;
      history.appendChild(row);
    });
  } catch (err) {
    status.textContent = "Unable to load evaluation history.";
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  loadUsers();
  loadHealth();
  loadModelSettings();
  loadAudit();
  initModelSettings();
  initEvaluation();
  loadEvaluationHistory();
});
