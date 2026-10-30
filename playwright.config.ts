import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  use: { baseURL: "http://127.0.0.1:8080", viewport: { width: 1440, height: 1100 } },
  webServer: {
    command: "python -m app.cli serve --demo",
    url: "http://127.0.0.1:8080",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
