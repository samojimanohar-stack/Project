const byId = (id) => document.getElementById(id);

const setStatus = (id, message) => {
  const el = byId(id);
  if (el) el.textContent = message;
};

const handleSignup = () => {
  const form = byId("signup-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("signup-status", "Creating account...");
    try {
      const res = await fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("signup-status", data.message || "Signup failed.");
        return;
      }
      window.location.href = "Template-dashboard.html";
    } catch (err) {
      setStatus("signup-status", "Signup failed. Try again.");
    }
  });
};

const handleLogin = () => {
  const form = byId("login-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("login-status", "Signing in...");
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("login-status", data.message || "Invalid credentials.");
        return;
      }
      window.location.href = "Template-dashboard.html";
    } catch (err) {
      setStatus("login-status", "Login failed. Try again.");
    }
  });
};

document.addEventListener("DOMContentLoaded", () => {
  handleSignup();
  handleLogin();
});
