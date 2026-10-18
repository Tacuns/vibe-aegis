#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const args = process.argv.slice(2);
const subcommand = args[0] || "setup";

if (subcommand === "setup" || subcommand === "install") {
  const forwardArgs = args.slice(1);
  const res = spawnSync("bash", [resolve(repoRoot, "install.sh"), ...forwardArgs], {
    stdio: "inherit",
  });
  process.exit(res.status ?? 0);
} else if (subcommand === "scan") {
  const forwardArgs = args.slice(1);
  const res = spawnSync("python3", [resolve(repoRoot, "scripts/aegis_scan.py"), ...forwardArgs], {
    stdio: "inherit",
  });
  process.exit(res.status ?? 0);
} else {
  console.log("Usage:");
  console.log("  npx vibe-aegis setup [--target <dir>] [--agent all|claude-code|vscode|codex|cursor]");
  console.log("  npx vibe-aegis scan [target-dir] [--url <live-url>] [--json]");
  process.exit(0);
}
