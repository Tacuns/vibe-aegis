#!/usr/bin/env bash
# =============================================================================
# Vibe Aegis (`vibe-aegis`) — Universal Cross-Agent Installer
# Installs the scanner, always-on prevention rules, slash commands, and
# multi-agent skills into any project or global environment for:
#   - Claude Code (`claude-code`)
#   - VS Code / GitHub Copilot (`vscode`)
#   - OpenAI Codex (`codex`)
#   - Cursor (`cursor`)
#   - Windsurf (`windsurf`)
#   - Cline / Roo Code (`cline`)
#   - Gemini CLI (`gemini`)
#   - All agents at once (`all`)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$(pwd)"
AGENT="all"
GLOBAL_INSTALL="false"

usage() {
  cat <<EOF
Usage: bash install.sh [OPTIONS]

Options:
  --target <path>    Target project directory (default: current directory)
  --agent <name>     Agent to configure: all | claude-code | vscode | codex | cursor | windsurf | cline | gemini
  --global           Install skills into user's global ~/.claude/skills and ~/.agents/skills directories
  -h, --help         Show this help message

Examples:
  bash install.sh --target /path/to/my-app --agent all
  bash install.sh --global --agent claude-code
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_DIR="$2"
      shift 2
      ;;
    --agent)
      AGENT="$2"
      shift 2
      ;;
    --global)
      GLOBAL_INSTALL="true"
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# -----------------------------------------------------------------------------
# File placement. Two kinds of file, never confused:
#
#   owned  - a file only Vibe Aegis writes: the scanner, our skills, our command,
#            our namespaced rule files. Kept current; if the copy on disk differs,
#            it is backed up first, so a local edit is never lost.
#   shared - a project's own config that other tools and people also write:
#            AGENTS.md, CLAUDE.md, copilot-instructions.md, tasks.json, .cursorrules,
#            .clinerules, GEMINI.md. Created only if absent. An existing one is NEVER
#            modified; our version is written to .aegis/suggested/ instead, and the
#            summary says so. This installer once overwrote a team's
#            .github/copilot-instructions.md with no backup.
#
# Re-running with nothing changed touches nothing.
# -----------------------------------------------------------------------------
BACKUP_STAMP="$(date +%Y%m%d-%H%M%S)"
KEPT_FILES=""
BACKED_UP=0

place_owned() {   # place_owned <src> <base> <relative-dest>
  local src="$1" base="$2" rel="$3"
  local dst="$base/$rel"
  if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
    return 0
  fi
  mkdir -p "$(dirname "$dst")"
  if [[ -f "$dst" ]]; then
    local bak="$base/.aegis/backup/$BACKUP_STAMP/$rel"
    mkdir -p "$(dirname "$bak")"
    cp -p "$dst" "$bak"
    BACKED_UP=$((BACKED_UP + 1))
  fi
  cp "$src" "$dst"
}

place_owned_tree() {   # place_owned_tree <src-dir> <base> <relative-dest-dir>
  local src_dir="$1" base="$2" rel_dir="$3" f
  while IFS= read -r f; do
    place_owned "$src_dir/$f" "$base" "$rel_dir/$f"
  done < <(cd "$src_dir" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
}

place_shared() {   # place_shared <src> <relative-dest>   (project installs only)
  local src="$1" rel="$2"
  local dst="$TARGET_DIR/$rel"
  if [[ ! -f "$dst" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
  elif ! cmp -s "$src" "$dst"; then
    local side="$TARGET_DIR/.aegis/suggested/$rel"
    mkdir -p "$(dirname "$side")"
    if ! { [[ -f "$side" ]] && cmp -s "$src" "$side"; }; then
      cp "$src" "$side"
    fi
    KEPT_FILES="$KEPT_FILES $rel"
  fi
}

report_kept_files() {
  if [[ -n "$KEPT_FILES" ]]; then
    echo ""
    echo "ℹ️  Kept your existing files unchanged:$KEPT_FILES"
    echo "   Vibe Aegis's versions are in .aegis/suggested/ - merge in what you want."
  fi
  if [[ "$BACKED_UP" -gt 0 ]]; then
    echo "ℹ️  Updated $BACKED_UP Vibe Aegis file(s) that differed; the previous copies are in"
    echo "   $1/.aegis/backup/$BACKUP_STAMP/"
  fi
}

if [[ "$GLOBAL_INSTALL" == "true" ]]; then
  echo "🛡️  Installing Vibe Aegis globally for user $(whoami)..."
  place_owned "$SCRIPT_DIR/scripts/aegis_scan.py" "$HOME" ".aegis/scripts/aegis_scan.py"
  chmod +x "$HOME/.aegis/scripts/aegis_scan.py"
  place_owned_tree "$SCRIPT_DIR/skills" "$HOME" ".claude/skills"
  place_owned_tree "$SCRIPT_DIR/skills" "$HOME" ".agents/skills"
  place_owned "$SCRIPT_DIR/adapters/claude/aegis.md" "$HOME" ".claude/commands/aegis.md"
  echo "✅ Global installation complete!"
  echo "   - Claude Code skills : ~/.claude/skills/"
  echo "   - Claude command     : ~/.claude/commands/aegis.md (/aegis)"
  echo "   - Codex/Agent skills : ~/.agents/skills/"
  echo "   - Scanner CLI        : python3 ~/.aegis/scripts/aegis_scan.py <project-dir>"
  report_kept_files "$HOME"
  exit 0
fi

mkdir -p "$TARGET_DIR"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

echo "🛡️  Installing Vibe Aegis into project: $TARGET_DIR (Agent mode: $AGENT)"

# 1. Always install the deterministic scanner & shared AGENTS.md
place_owned "$SCRIPT_DIR/scripts/aegis_scan.py" "$TARGET_DIR" ".aegis/scripts/aegis_scan.py"
chmod +x "$TARGET_DIR/.aegis/scripts/aegis_scan.py"
place_shared "$SCRIPT_DIR/AGENTS.md" "AGENTS.md"

install_claude() {
  place_owned_tree "$SCRIPT_DIR/skills" "$TARGET_DIR" ".claude/skills"
  place_owned "$SCRIPT_DIR/adapters/claude/aegis.md" "$TARGET_DIR" ".claude/commands/aegis.md"
  place_shared "$SCRIPT_DIR/CLAUDE.md" "CLAUDE.md"
  echo "   ✓ Configured Claude Code (.claude/skills/, .claude/commands/aegis.md, CLAUDE.md)"
}

install_vscode() {
  place_owned_tree "$SCRIPT_DIR/skills" "$TARGET_DIR" ".github/skills"
  place_owned "$SCRIPT_DIR/adapters/vscode/aegis-audit.prompt.md" "$TARGET_DIR" ".github/prompts/aegis-audit.prompt.md"
  place_shared "$SCRIPT_DIR/adapters/vscode/copilot-instructions.md" ".github/copilot-instructions.md"
  place_shared "$SCRIPT_DIR/adapters/vscode/tasks.json" ".vscode/tasks.json"
  echo "   ✓ Configured VS Code & GitHub Copilot (.github/copilot-instructions.md, .github/prompts/, .github/skills/)"
}

install_codex() {
  place_owned_tree "$SCRIPT_DIR/skills" "$TARGET_DIR" ".agents/skills"
  echo "   ✓ Configured OpenAI Codex (.agents/skills/, AGENTS.md)"
}

install_cursor() {
  place_owned "$SCRIPT_DIR/adapters/cursor/vibe-aegis.mdc" "$TARGET_DIR" ".cursor/rules/vibe-aegis.mdc"
  place_owned_tree "$SCRIPT_DIR/skills" "$TARGET_DIR" ".cursor/skills"
  place_shared "$SCRIPT_DIR/AGENTS.md" ".cursorrules"
  echo "   ✓ Configured Cursor (.cursor/rules/vibe-aegis.mdc, .cursor/skills/, .cursorrules)"
}

install_windsurf_cline_gemini() {
  place_owned "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR" ".windsurf/rules/vibe-aegis.md"
  place_shared "$SCRIPT_DIR/AGENTS.md" ".clinerules"
  place_shared "$SCRIPT_DIR/AGENTS.md" "GEMINI.md"
  echo "   ✓ Configured Windsurf, Cline & Gemini CLI (.windsurf/rules/, .clinerules, GEMINI.md)"
}

case "$AGENT" in
  all)
    install_claude
    install_vscode
    install_codex
    install_cursor
    install_windsurf_cline_gemini
    ;;
  claude-code|claude)
    install_claude
    ;;
  vscode|copilot)
    install_vscode
    ;;
  codex)
    install_codex
    ;;
  cursor)
    install_cursor
    ;;
  windsurf|cline|gemini)
    install_windsurf_cline_gemini
    ;;
  *)
    echo "Unknown agent '$AGENT'. Supported: all | claude-code | vscode | codex | cursor | windsurf | cline | gemini" >&2
    exit 1
    ;;
esac

echo ""
echo "✅ Vibe Aegis installed in $TARGET_DIR!"
echo "   Run quick scan : python3 .aegis/scripts/aegis_scan.py ."
echo "   In Claude Code : /aegis  (or /aegis --fix)"
echo "   In VS Code     : /aegis-audit in Copilot Chat"
echo "   In Codex/Cursor: Ask 'Run the Vibe Aegis security and UI/UX audit loop'"
report_kept_files "$TARGET_DIR"
