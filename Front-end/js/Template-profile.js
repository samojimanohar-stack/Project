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

const loadProfile = async () => {
  try {
    const res = await fetch("/api/profile");
    const data = await res.json();
    if (!res.ok) {
      setStatus("profile-status", data.message || "Unable to load profile.");
      return;
    }
    const user = data.user || {};
    byId("profile-name").value = user.name || "";
    byId("profile-email").value = user.email || "";
    byId("profile-role").value = user.role || "";
    const meta = byId("profile-meta");
    if (meta) {
      meta.innerHTML = `
        <span class="status-pill ${user.login_count ? "status-active" : "status-disabled"}">
          ${user.login_count ? "Returning" : "New"}
        </span>
        <span class="muted">Created: ${user.created_at || "--"}</span>
        <span class="muted">Last login: ${user.last_login || "--"}</span>
      `;
    }
    setStatus("profile-status", "Profile loaded.");
  } catch (err) {
    setStatus("profile-status", "Unable to load profile.");
  }
};

const handleProfileSave = () => {
  const form = byId("profile-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = byId("profile-name").value.trim();
    if (!name) {
      setStatus("profile-status", "Name is required.");
      return;
    }
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/profile", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ name }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("profile-status", data.message || "Update failed.");
        return;
      }
      setStatus("profile-status", "Profile updated.");
      loadProfile();
    } catch (err) {
      setStatus("profile-status", "Update failed.");
    }
  });
};

const handlePasswordChange = () => {
  const form = byId("password-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const current_password = byId("current-password").value.trim();
    const new_password = byId("new-password").value.trim();
    if (!current_password || !new_password) {
      setStatus("password-status", "Both fields are required.");
      return;
    }
    setStatus("password-status", "Updating password...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ current_password, new_password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("password-status", data.message || "Password update failed.");
        return;
      }
      setStatus("password-status", "Password updated.");
      byId("current-password").value = "";
      byId("new-password").value = "";
    } catch (err) {
      setStatus("password-status", "Password update failed.");
    }
  });
};

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  loadProfile();
  handleProfileSave();
  handlePasswordChange();
});
