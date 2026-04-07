import fs from "fs/promises";
import path from "path";

const phase = process.argv[2] ?? "build";
const outputPath = path.join(process.cwd(), "public", "build-metadata.json");
const timestamp = new Date().toISOString();

const payload = {
  phase,
  generatedAt: timestamp,
  nodeVersion: process.version,
  platform: process.platform,
  arch: process.arch,
  railway: {
    environment: process.env.RAILWAY_ENVIRONMENT ?? null,
    projectId: process.env.RAILWAY_PROJECT_ID ?? null,
  },
  webhook: {
    enabled: Boolean(process.env.WEBHOOK_SITE_URL),
    sent: false,
    status: null,
    error: null,
  },
};

if (process.env.WEBHOOK_SITE_URL) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(process.env.WEBHOOK_SITE_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Node.js Server Info Build",
      },
      body: JSON.stringify({
        phase,
        timestamp,
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        railwayEnvironment: process.env.RAILWAY_ENVIRONMENT ?? null,
        railwayProjectId: process.env.RAILWAY_PROJECT_ID ?? null,
      }),
    });
    clearTimeout(timeoutId);

    payload.webhook.sent = response.ok;
    payload.webhook.status = response.status;
  } catch (error) {
    payload.webhook.error = error instanceof Error ? error.message : "Request failed";
  }
}

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

if (payload.webhook.enabled) {
  console.log(`Webhook ${payload.webhook.sent ? "sent" : "failed"} for ${phase}`);
} else {
  console.log("WEBHOOK_SITE_URL not set; skipped webhook notification");
}