import { test, expect } from "@playwright/test";

test("login page loads", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
});

test("signup page loads", async ({ page }) => {
  await page.goto("/signup");
  await expect(page.getByRole("heading", { name: /create/i })).toBeVisible();
});

test("dashboard redirects to login when not authenticated", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);
});

test("admin redirects to login when not authenticated", async ({ page }) => {
  await page.goto("/admin");
  await expect(page).toHaveURL(/\/login/);
});

test("signup -> login -> dashboard (email verification bypass)", async ({ page }) => {
  const email = `test_${Date.now()}@example.com`;
  const password = "Test1234";

  await page.goto("/signup");
  await page.getByLabel(/name/i).fill("Playwright User");
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/^password$/i).fill(password);
  await page.getByLabel(/confirm/i).fill(password);
  await page.getByRole("button", { name: /create/i }).click();

  // Manually mark verified via API (dev-only pattern)
  await page.goto("/login");
  await page.evaluate(async (email) => {
    await fetch("/api/request-verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
  }, email);

  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/dashboard/);
});

test("csv upload shows summary", async ({ page }) => {
  const email = `ui_user_${Date.now()}@example.com`;
  const password = "Test1234";
  await page.request.post("/api/test/create-user", {
    data: { email, password, role: "analyst", name: "UI User" },
  });
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/dashboard/);

  const fileChooser = page.locator('input[type="file"][name="file"]');
  await fileChooser.setInputFiles("Front-end/csv/sample.csv");
  await page.getByRole("button", { name: /upload/i }).click();
  await expect(page.getByText(/csv processed successfully/i)).toBeVisible();
  await expect(page.locator("#csv-summary")).toContainText("Rows:");

  await page.request.delete("/api/test/delete-user", { data: { email } });
});

test("admin page loads after login", async ({ page }) => {
  const adminEmail = `ui_admin_${Date.now()}@example.com`;
  const adminPassword = "Admin1234";
  await page.request.post("/api/test/create-user", {
    data: { email: adminEmail, password: adminPassword, role: "admin", name: "UI Admin" },
  });
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(adminEmail);
  await page.getByLabel(/password/i).fill(adminPassword);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: /admin console/i })).toBeVisible();

  await page.request.delete("/api/test/delete-user", { data: { email: adminEmail } });
});
