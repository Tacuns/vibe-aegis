"""Release gate: run `--profile release` on controlled fixtures and assert the exact
verdict and exit code of each. CI runs this; it needs the OSV API for the clean case.

    python3 tests/release_gate/run.py

Each fixture is copied to a temporary directory and committed to a fresh git repository
(full history, not shallow), so every release stage has real evidence to read.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANNER = HERE.parent.parent / "scripts" / "aegis_scan.py"

# fixture: (leading word of release_verdict, exit code)
EXPECTED = {
    "clean": ("RELEASE_AUDIT_PASSED", 0),
    "vulnerable": ("BLOCKED", 1),
    "review": ("REVIEW_REQUIRED", 1),
    "incomplete": ("INCOMPLETE_SCAN", 1),
}


def run(name: str):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / name
        shutil.copytree(HERE / name, root)
        # Stored as dist.fixture/: the repository's .gitignore rightly excludes dist/.
        for stored in list(root.rglob("dist.fixture")):
            stored.rename(stored.parent / "dist")
        git = ["git", "-c", "user.name=gate", "-c", "user.email=gate@localhost",
               "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q"], cwd=root, check=True)
        subprocess.run(git + ["add", "-A"], cwd=root, check=True)
        subprocess.run(git + ["commit", "-q", "-m", "fixture"], cwd=root, check=True)
        report = Path(tmp) / "report.json"
        proc = subprocess.run([sys.executable, str(SCANNER), str(root), "--profile", "release",
                               "--quiet", "--output", str(report)],
                              capture_output=True, text=True, timeout=600)
        data = json.loads(report.read_text(encoding="utf-8"))
        return data["release_verdict"], proc.returncode, [s["title"] for s in data["skipped_checks"]]


def main() -> int:
    failures = 0
    for name, (verdict, code) in EXPECTED.items():
        got_verdict, got_code, gaps = run(name)
        ok = got_verdict.split(" ")[0] == verdict and got_code == code
        failures += not ok
        print("%-11s %-4s verdict=%s exit=%d%s" % (
            name, "ok" if ok else "FAIL", got_verdict.split(" ")[0], got_code,
            "" if ok else "  (expected %s / %d; gaps: %s)" % (verdict, code, gaps)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
