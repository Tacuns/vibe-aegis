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
  // "python3" does not exist on a default Windows install; try the common names
  // in order and report clearly rather than failing with ENOENT.
  const candidates = process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"];
  const scanner = resolve(repoRoot, "scripts/aegis_scan.py");
  let res = null;
  for (const bin of candidates) {
    res = spawnSync(bin, [scanner, ...forwardArgs], { stdio: "inherit" });
    if (!res.error) break;
  }
  if (res && res.error) {
    console.error(
      `vibe-aegis: could not find a Python interpreter (tried: ${candidates.join(", ")}).
` +
      "Install Python 3.8+ and ensure it is on your PATH."
    );
    process.exit(127);
  }
  process.exit(res?.status ?? 0);
} else {
  console.log("Usage:");
  console.log("  npx vibe-aegis setup [--target <dir>] [--agent all|claude-code|vscode|codex|cursor]");
  console.log("  npx vibe-aegis scan [target-dir] [--url <live-url>] [--json]");
  process.exit(0);
}
