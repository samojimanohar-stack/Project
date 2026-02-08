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
      row.innerHTML = `
        <div>${user.name}</div>
        <div class="muted">${user.email}</div>
        <div class="admin-badge">${user.role}</div>
        <div class="muted">${user.active ? "Active" : "Disabled"}</div>
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

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  loadUsers();
});
