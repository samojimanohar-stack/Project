const byId = (id) => document.getElementById(id);
let csrfToken = "";
let users = [];
let selectedUser = null;

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

const fetchUsers = async () => {
  const status = byId("user-list-status");
  if (status) status.textContent = "Loading users...";
  try {
    const res = await fetch("/api/admin/users");
    const data = await res.json();
    if (!res.ok) {
      setStatus("user-list-status", data.message || "Unable to load users.");
      return;
    }
    users = data.users || [];
    renderUserList();
    setStatus("user-list-status", users.length ? "" : "No users found.");
  } catch (err) {
    setStatus("user-list-status", "Unable to load users.");
  }
};

const filteredUsers = () => {
  const query = byId("user-search")?.value?.trim().toLowerCase() || "";
  const role = byId("user-role-filter")?.value || "all";
  const status = byId("user-status-filter")?.value || "all";
  return users.filter((user) => {
    const matchQuery =
      !query ||
      user.name.toLowerCase().includes(query) ||
      user.email.toLowerCase().includes(query);
    const matchRole = role === "all" || user.role === role;
    const matchStatus =
      status === "all" ||
      (status === "active" && user.active) ||
      (status === "disabled" && !user.active);
    return matchQuery && matchRole && matchStatus;
  });
};

const renderUserList = () => {
  const list = byId("user-list");
  if (!list) return;
  list.innerHTML = "";
  const items = filteredUsers();
  items.forEach((user) => {
    const row = document.createElement("div");
    row.className = "admin-row admin-row-click";
    row.dataset.userId = user.id;
    row.innerHTML = `
      <div>
        <div class="admin-name">${user.name}</div>
        <div class="muted">${user.email}</div>
      </div>
      <div class="admin-badge">${user.role}</div>
      <div class="status-pill ${user.active ? "status-active" : "status-disabled"}">
        ${user.active ? "Active" : "Disabled"}
      </div>
      <div class="muted">${user.email_verified ? "Verified" : "Unverified"}</div>
    `;
    row.addEventListener("click", () => selectUser(user.id));
    list.appendChild(row);
  });
};

const selectUser = async (userId) => {
  const status = byId("user-detail-status");
  if (status) status.textContent = "Loading user...";
  try {
    const res = await fetch(`/api/admin/user/${userId}`);
    const data = await res.json();
    if (!res.ok) {
      setStatus("user-detail-status", data.message || "Unable to load user.");
      return;
    }
    selectedUser = data.user;
    hydrateDetail(selectedUser);
  } catch (err) {
    setStatus("user-detail-status", "Unable to load user.");
  }
};

const hydrateDetail = (user) => {
  byId("detail-name").value = user.name || "";
  byId("detail-email").value = user.email || "";
  byId("detail-role").value = user.role || "analyst";
  byId("detail-active").checked = !!user.active;
  const meta = byId("detail-meta");
  if (meta) {
    meta.innerHTML = `
      <span class="status-pill ${user.email_verified ? "status-active" : "status-disabled"}">
        ${user.email_verified ? "Verified" : "Unverified"}
      </span>
      <span class="muted">Created: ${user.created_at || "--"}</span>
    `;
  }
  setStatus("user-detail-status", `Editing user #${user.id}`);
};

const handleFilters = () => {
  ["user-search", "user-role-filter", "user-status-filter"].forEach((id) => {
    const el = byId(id);
    if (el) el.addEventListener("input", renderUserList);
  });
};

const handleExport = () => {
  const button = byId("user-export");
  if (!button) return;
  button.addEventListener("click", () => {
    const rows = filteredUsers();
    if (!rows.length) return;
    const headers = ["id", "name", "email", "role", "active", "email_verified", "created_at"];
    const csv = [
      headers.join(","),
      ...rows.map((u) =>
        headers
          .map((h) => `"${String(u[h] ?? "").replace(/"/g, '""')}"`)
          .join(",")
      ),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "users.csv";
    link.click();
    URL.revokeObjectURL(url);
  });
};

const handleDetailSave = () => {
  const form = byId("user-detail-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedUser) {
      setStatus("user-detail-status", "Select a user first.");
      return;
    }
    const payload = {
      user_id: selectedUser.id,
      name: byId("detail-name").value.trim(),
      role: byId("detail-role").value,
      active: byId("detail-active").checked ? 1 : 0,
    };
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/admin/user", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("user-detail-status", data.message || "Update failed.");
        return;
      }
      setStatus("user-detail-status", "User updated.");
      await fetchUsers();
    } catch (err) {
      setStatus("user-detail-status", "Update failed.");
    }
  });
};

const handleReset = () => {
  const button = byId("detail-reset");
  if (!button) return;
  button.addEventListener("click", async () => {
    if (!selectedUser) {
      setStatus("user-detail-status", "Select a user first.");
      return;
    }
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/admin/user/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ user_id: selectedUser.id }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("user-detail-status", data.message || "Reset failed.");
        return;
      }
      setStatus(
        "user-detail-status",
        data.reset_url ? `Reset link: ${data.reset_url}` : "Reset link sent."
      );
    } catch (err) {
      setStatus("user-detail-status", "Reset failed.");
    }
  });
};

const handleDelete = () => {
  const button = byId("detail-delete");
  if (!button) return;
  button.addEventListener("click", async () => {
    if (!selectedUser) {
      setStatus("user-detail-status", "Select a user first.");
      return;
    }
    const confirmDelete = window.confirm(
      `Delete user ${selectedUser.email}? This cannot be undone.`
    );
    if (!confirmDelete) return;
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch(`/api/admin/user/${selectedUser.id}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": csrfToken },
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("user-detail-status", data.message || "Delete failed.");
        return;
      }
      setStatus("user-detail-status", "User deleted.");
      selectedUser = null;
      formReset();
      await fetchUsers();
    } catch (err) {
      setStatus("user-detail-status", "Delete failed.");
    }
  });
};

const formReset = () => {
  byId("detail-name").value = "";
  byId("detail-email").value = "";
  byId("detail-role").value = "analyst";
  byId("detail-active").checked = true;
  const meta = byId("detail-meta");
  if (meta) meta.innerHTML = "";
};

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  fetchUsers();
  handleFilters();
  handleExport();
  handleDetailSave();
  handleReset();
  handleDelete();
});
