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

if [[ "$GLOBAL_INSTALL" == "true" ]]; then
  echo "🛡️  Installing Vibe Aegis globally for user $(whoami)..."
  mkdir -p "$HOME/.claude/skills" "$HOME/.claude/commands" "$HOME/.agents/skills" "$HOME/.aegis/scripts"
  cp "$SCRIPT_DIR/scripts/aegis_scan.py" "$HOME/.aegis/scripts/aegis_scan.py"
  chmod +x "$HOME/.aegis/scripts/aegis_scan.py"
  cp -r "$SCRIPT_DIR/skills/"* "$HOME/.claude/skills/"
  cp -r "$SCRIPT_DIR/skills/"* "$HOME/.agents/skills/"
  cp "$SCRIPT_DIR/adapters/claude/aegis.md" "$HOME/.claude/commands/aegis.md"
  echo "✅ Global installation complete!"
  echo "   - Claude Code skills : ~/.claude/skills/{vibe-aegis,security-redteam-loop,ui-ux-bug-finder}"
  echo "   - Claude command     : ~/.claude/commands/aegis.md (/aegis)"
  echo "   - Codex/Agent skills : ~/.agents/skills/{vibe-aegis,security-redteam-loop,ui-ux-bug-finder}"
  echo "   - Scanner CLI        : python3 ~/.aegis/scripts/aegis_scan.py <project-dir>"
  exit 0
fi

mkdir -p "$TARGET_DIR"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

echo "🛡️  Installing Vibe Aegis into project: $TARGET_DIR (Agent mode: $AGENT)"

# 1. Always install the deterministic scanner & shared AGENTS.md
mkdir -p "$TARGET_DIR/.aegis/scripts"
cp "$SCRIPT_DIR/scripts/aegis_scan.py" "$TARGET_DIR/.aegis/scripts/aegis_scan.py"
chmod +x "$TARGET_DIR/.aegis/scripts/aegis_scan.py"

# Idempotent: if the project has no AGENTS.md we own it and keep it current.
# If one already exists we never clobber it - but we also must not create a
# second artefact on every re-run, so the side copy is written in place.
if [[ ! -f "$TARGET_DIR/AGENTS.md" ]]; then
  cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/AGENTS.md"
elif cmp -s "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/AGENTS.md"; then
  : # already ours and identical - nothing to do
else
  cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/.aegis/AGENTS.vibe-aegis.md"
fi

install_claude() {
  mkdir -p "$TARGET_DIR/.claude/skills" "$TARGET_DIR/.claude/commands"
  cp -r "$SCRIPT_DIR/skills/"* "$TARGET_DIR/.claude/skills/"
  cp "$SCRIPT_DIR/adapters/claude/aegis.md" "$TARGET_DIR/.claude/commands/aegis.md"
  if [[ ! -f "$TARGET_DIR/CLAUDE.md" ]]; then
    cp "$SCRIPT_DIR/CLAUDE.md" "$TARGET_DIR/CLAUDE.md"
  fi
  echo "   ✓ Configured Claude Code (.claude/skills/, .claude/commands/aegis.md, CLAUDE.md)"
}

install_vscode() {
  mkdir -p "$TARGET_DIR/.github/skills" "$TARGET_DIR/.github/prompts" "$TARGET_DIR/.vscode"
  cp -r "$SCRIPT_DIR/skills/"* "$TARGET_DIR/.github/skills/"
  cp "$SCRIPT_DIR/adapters/vscode/copilot-instructions.md" "$TARGET_DIR/.github/copilot-instructions.md"
  cp "$SCRIPT_DIR/adapters/vscode/aegis-audit.prompt.md" "$TARGET_DIR/.github/prompts/aegis-audit.prompt.md"
  if [[ ! -f "$TARGET_DIR/.vscode/tasks.json" ]]; then
    cp "$SCRIPT_DIR/adapters/vscode/tasks.json" "$TARGET_DIR/.vscode/tasks.json"
  fi
  echo "   ✓ Configured VS Code & GitHub Copilot (.github/copilot-instructions.md, .github/prompts/, .github/skills/)"
}

install_codex() {
  mkdir -p "$TARGET_DIR/.agents/skills"
  cp -r "$SCRIPT_DIR/skills/"* "$TARGET_DIR/.agents/skills/"
  echo "   ✓ Configured OpenAI Codex (.agents/skills/, AGENTS.md)"
}

install_cursor() {
  mkdir -p "$TARGET_DIR/.cursor/rules" "$TARGET_DIR/.cursor/skills"
  cp "$SCRIPT_DIR/adapters/cursor/vibe-aegis.mdc" "$TARGET_DIR/.cursor/rules/vibe-aegis.mdc"
  cp -r "$SCRIPT_DIR/skills/"* "$TARGET_DIR/.cursor/skills/"
  if [[ ! -f "$TARGET_DIR/.cursorrules" ]]; then
    cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/.cursorrules"
  fi
  echo "   ✓ Configured Cursor (.cursor/rules/vibe-aegis.mdc, .cursor/skills/, .cursorrules)"
}

install_windsurf_cline_gemini() {
  mkdir -p "$TARGET_DIR/.windsurf/rules"
  cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/.windsurf/rules/vibe-aegis.md"
  if [[ ! -f "$TARGET_DIR/.clinerules" ]]; then
    cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/.clinerules"
  fi
  if [[ ! -f "$TARGET_DIR/GEMINI.md" ]]; then
    cp "$SCRIPT_DIR/AGENTS.md" "$TARGET_DIR/GEMINI.md"
  fi
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
