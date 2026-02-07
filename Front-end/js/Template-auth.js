const byId = (id) => document.getElementById(id);
let csrfToken = "";

const setStatus = (id, message) => {
  const el = byId(id);
  if (el) el.textContent = message;
};

const initCsrf = async () => {
  try {
    const res = await fetch("/api/csrf");
    const data = await res.json();
    if (res.ok) csrfToken = data.token;
  } catch (err) {
    csrfToken = "";
  }
};

const handleSignup = () => {
  const form = byId("signup-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("signup-status", "Creating account...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("signup-status", data.message || "Signup failed.");
        return;
      }
      if (data.verify_url) {
        setStatus(
          "signup-status",
          `Verify your email to continue. Dev link: ${data.verify_url}`
        );
        return;
      }
      setStatus("signup-status", "Account created. Verify your email.");
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
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("login-status", data.message || "Invalid credentials.");
        return;
      }
      window.location.href = "/dashboard";
    } catch (err) {
      setStatus("login-status", "Login failed. Try again.");
    }
  });
};

const handleForgot = () => {
  const form = byId("forgot-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("forgot-status", "Sending reset link...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/request-password-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("forgot-status", data.message || "Request failed.");
        return;
      }
      if (data.reset_url) {
        setStatus(
          "forgot-status",
          "We opened the reset page for you. If email is configured, check your inbox too."
        );
        window.location.href = data.reset_url;
        return;
      }
      setStatus("forgot-status", "Reset link sent. Check your email.");
    } catch (err) {
      setStatus("forgot-status", "Request failed. Try again.");
    }
  });
};

const handleReset = () => {
  const form = byId("reset-form");
  if (!form) return;
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token") || "";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    payload.token = token;
    setStatus("reset-status", "Updating password...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("reset-status", data.message || "Reset failed.");
        return;
      }
      setStatus("reset-status", "Password updated. You can sign in.");
    } catch (err) {
      setStatus("reset-status", "Reset failed. Try again.");
    }
  });
};

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  handleSignup();
  handleLogin();
  handleForgot();
  handleReset();
});
