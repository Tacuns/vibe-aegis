#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { constants } from "node:os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

const args = process.argv.slice(2);
const subcommand = args[0] || "setup";

// The child's own exit status, never a guessed success. `status` is null when the child
// was killed by a signal (Ctrl-C, OOM killer, CI timeout) - `?? 0` turned that into a
// passing exit. Report it the way a shell does: 128 + the signal number.
function exitLikeChild(res, what) {
  if (res.error) {
    console.error(`vibe-aegis: could not run ${what}: ${res.error.message}`);
    process.exit(127);
  }
  if (res.status !== null) process.exit(res.status);
  const signo = res.signal ? constants.signals[res.signal] : undefined;
  console.error(`vibe-aegis: ${what} was terminated${res.signal ? ` by ${res.signal}` : ""} ` +
    "and did not complete.");
  process.exit(signo ? 128 + signo : 1);
}

function usage(stream) {
  stream("Usage:");
  stream("  npx vibe-aegis setup [--target <dir>] [--agent all|claude-code|vscode|codex|cursor]");
  stream("  npx vibe-aegis scan [target-dir] [--url <live-url>] [--json]");
}

if (subcommand === "setup" || subcommand === "install") {
  const forwardArgs = args.slice(1);
  const res = spawnSync("bash", [resolve(repoRoot, "install.sh"), ...forwardArgs], {
    stdio: "inherit",
  });
  exitLikeChild(res, "the installer (bash)");
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
  exitLikeChild(res, "the scanner");
} else if (["help", "--help", "-h"].includes(subcommand)) {
  usage(console.log);
  process.exit(0);
} else {
  // An unknown command did nothing; exiting 0 let a typo (`scna`) pass a CI step.
  console.error(`vibe-aegis: unknown command "${subcommand}"`);
  usage(console.error);
  process.exit(2);
}
