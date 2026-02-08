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

const showResendForm = (message) => {
  const form = byId("resend-form");
  if (!form) return;
  form.classList.remove("is-hidden");
  if (message) setStatus("reset-resend-status", message);
};

const showResetSuccess = (message) => {
  const banner = byId("reset-success-banner");
  if (banner) {
    banner.textContent = message || "Password updated. Redirecting to sign in...";
    banner.classList.remove("is-hidden");
  }
  const resetForm = byId("reset-form");
  if (resetForm) resetForm.classList.add("is-hidden");
  const resendForm = byId("resend-form");
  if (resendForm) resendForm.classList.add("is-hidden");
};

const handleSignup = () => {
  const form = byId("signup-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    if (
      payload.confirm_password &&
      payload.password &&
      payload.confirm_password !== payload.password
    ) {
      setStatus("signup-status", "Passwords do not match.");
      return;
    }
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
  if (!token) {
    setStatus("reset-status", "Reset link is missing or invalid.");
    const submit = form.querySelector("button[type='submit']");
    if (submit) submit.disabled = true;
    showResendForm("Enter your email to receive a new reset link.");
    return;
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    if (
      payload.confirm_password &&
      payload.password &&
      payload.confirm_password !== payload.password
    ) {
      setStatus("reset-status", "Passwords do not match.");
      return;
    }
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
        const message = data.message || "Reset failed.";
        setStatus("reset-status", message);
        if (message.toLowerCase().includes("expired") || message.toLowerCase().includes("invalid")) {
          showResendForm("Your reset link is invalid or expired. Request a new one below.");
        }
        return;
      }
      showResetSuccess("Password updated. Redirecting to sign in...");
      window.location.replace("/login");
    } catch (err) {
      setStatus("reset-status", "Reset failed. Try again.");
    }
  });
};

const initPasswordToggles = () => {
  const toggles = document.querySelectorAll(".password-toggle");
  toggles.forEach((toggle) => {
    const field = toggle.closest(".password-field");
    const input = field ? field.querySelector("input") : null;
    if (!input) return;
    toggle.addEventListener("click", () => {
      const isHidden = input.type === "password";
      input.type = isHidden ? "text" : "password";
      toggle.textContent = isHidden ? "Hide" : "Show";
      toggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    });
  });
};

const handleResend = () => {
  const form = byId("resend-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    setStatus("reset-resend-status", "Sending reset link...");
    try {
      if (!csrfToken) await initCsrf();
      const res = await fetch("/api/request-password-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus("reset-resend-status", data.message || "Request failed.");
        return;
      }
      if (data.reset_url) {
        setStatus(
          "reset-resend-status",
          "We opened the reset page for you. If email is configured, check your inbox too."
        );
        window.location.href = data.reset_url;
        return;
      }
      setStatus("reset-resend-status", "Reset link sent. Check your email.");
    } catch (err) {
      setStatus("reset-resend-status", "Request failed. Try again.");
    }
  });
};

document.addEventListener("DOMContentLoaded", () => {
  initCsrf();
  handleSignup();
  handleLogin();
  handleForgot();
  handleReset();
  handleResend();
  initPasswordToggles();
});
