#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="virgil"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/skills/$SKILL_NAME"

if [[ ! -f "$SOURCE_DIR/SKILL.md" ]]; then
  echo "Error: source skill not found at $SOURCE_DIR/SKILL.md" >&2
  exit 1
fi

AGENTS_INPUT=()
SCOPE="global"
TARGET_REPO="$(pwd)"
LINK_MODE=0
DRY_RUN=0
UNINSTALL=0

VALID_AGENTS=(claude gemini antigravity hermes codex cursor agents)

usage() {
  cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Options:
  --agent <list>     Comma-separated or repeated agent targets:
                     auto (default), all, claude, gemini, antigravity,
                     hermes, codex, cursor, agents
  --scope <scope>    global (default) or project
  --target <dir>     Target project directory when --scope project (default: cwd)
  --link             Symlink skill directory instead of copying
  --dry-run          Print planned changes without writing files
  --uninstall        Remove installed virgil skill for selected targets
  -h, --help         Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      [[ $# -ge 2 ]] || { echo "Error: --agent requires a value" >&2; exit 1; }
      AGENTS_INPUT+=("$2")
      shift 2
      ;;
    --scope)
      [[ $# -ge 2 ]] || { echo "Error: --scope requires a value" >&2; exit 1; }
      SCOPE="$2"
      if [[ "$SCOPE" != "global" && "$SCOPE" != "project" ]]; then
        echo "Error: --scope must be 'global' or 'project'" >&2
        exit 1
      fi
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || { echo "Error: --target requires a value" >&2; exit 1; }
      TARGET_REPO="$2"
      shift 2
      ;;
    --link)
      LINK_MODE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ${#AGENTS_INPUT[@]} -eq 0 ]]; then
  AGENTS_INPUT=("auto")
fi

if [[ "$SCOPE" == "project" ]]; then
  if [[ ! -d "$TARGET_REPO" ]]; then
    echo "Error: target directory does not exist: $TARGET_REPO" >&2
    exit 1
  fi
  TARGET_REPO="$(cd "$TARGET_REPO" && pwd)"
fi

is_valid_agent() {
  local cand="$1"
  local a
  for a in "${VALID_AGENTS[@]}"; do
    if [[ "$a" == "$cand" ]]; then
      return 0
    fi
  done
  return 1
}

get_target_path() {
  local agent="$1"
  if [[ "$SCOPE" == "global" ]]; then
    case "$agent" in
      claude)      echo "$HOME/.claude/skills/$SKILL_NAME" ;;
      gemini)      echo "$HOME/.gemini/skills/$SKILL_NAME" ;;
      antigravity) echo "$HOME/.gemini/config/skills/$SKILL_NAME" ;;
      hermes)      echo "$HOME/.hermes/skills/$SKILL_NAME" ;;
      codex)       echo "$HOME/.codex/skills/$SKILL_NAME" ;;
      cursor)      echo "$HOME/.cursor/skills/$SKILL_NAME" ;;
      agents)      echo "$HOME/.agents/skills/$SKILL_NAME" ;;
    esac
  else
    case "$agent" in
      claude)      echo "$TARGET_REPO/.claude/skills/$SKILL_NAME" ;;
      gemini)      echo "$TARGET_REPO/.gemini/skills/$SKILL_NAME" ;;
      antigravity) echo "$TARGET_REPO/.agents/skills/$SKILL_NAME" ;;
      hermes)      echo "$TARGET_REPO/.hermes/skills/$SKILL_NAME" ;;
      codex)       echo "$TARGET_REPO/.codex/skills/$SKILL_NAME" ;;
      cursor)      echo "$TARGET_REPO/.cursor/skills/$SKILL_NAME" ;;
      agents)      echo "$TARGET_REPO/.agents/skills/$SKILL_NAME" ;;
    esac
  fi
}

SELECTED_AGENTS=()
add_agent() {
  local item="$1"
  local existing
  for existing in "${SELECTED_AGENTS[@]+"${SELECTED_AGENTS[@]}"}"; do
    if [[ "$existing" == "$item" ]]; then
      return 0
    fi
  done
  SELECTED_AGENTS+=("$item")
}

resolve_auto() {
  local found=0
  if [[ "$SCOPE" == "global" ]]; then
    [[ -d "$HOME/.claude" ]] && { add_agent "claude"; found=1; }
    [[ -d "$HOME/.gemini" ]] && { add_agent "gemini"; found=1; }
    [[ -d "$HOME/.gemini/config" ]] && { add_agent "antigravity"; found=1; }
    [[ -d "$HOME/.hermes" ]] && { add_agent "hermes"; found=1; }
    [[ -d "$HOME/.codex" ]] && { add_agent "codex"; found=1; }
    [[ -d "$HOME/.cursor" ]] && { add_agent "cursor"; found=1; }
    [[ -d "$HOME/.agents" ]] && { add_agent "agents"; found=1; }
    if [[ $found -eq 0 ]]; then
      add_agent "agents"
    fi
  else
    add_agent "agents"
    [[ -d "$TARGET_REPO/.claude" ]] && add_agent "claude"
    [[ -d "$TARGET_REPO/.gemini" ]] && add_agent "gemini"
    [[ -d "$TARGET_REPO/.hermes" ]] && add_agent "hermes"
    [[ -d "$TARGET_REPO/.codex" ]] && add_agent "codex"
    [[ -d "$TARGET_REPO/.cursor" ]] && add_agent "cursor"
  fi
}

for raw in "${AGENTS_INPUT[@]}"; do
  IFS=',' read -ra parts <<< "$raw"
  for part in "${parts[@]}"; do
    tok="$(echo "$part" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ -z "$tok" ]] && continue
    if [[ "$tok" == "all" ]]; then
      for a in "${VALID_AGENTS[@]}"; do add_agent "$a"; done
    elif [[ "$tok" == "auto" ]]; then
      resolve_auto
    elif is_valid_agent "$tok"; then
      add_agent "$tok"
    else
      echo "Error: unknown agent '$tok'. Valid options: auto, all, ${VALID_AGENTS[*]}" >&2
      exit 1
    fi
  done
done

DEDUP_PATHS=()
DEDUP_LABELS=()

for a in "${SELECTED_AGENTS[@]}"; do
  dest="$(get_target_path "$a")"
  matched_idx=-1
  for i in "${!DEDUP_PATHS[@]}"; do
    if [[ "${DEDUP_PATHS[$i]}" == "$dest" ]]; then
      matched_idx=$i
      break
    fi
  done
  if [[ $matched_idx -ge 0 ]]; then
    DEDUP_LABELS[$matched_idx]="${DEDUP_LABELS[$matched_idx]},$a"
  else
    DEDUP_PATHS+=("$dest")
    DEDUP_LABELS+=("$a")
  fi
done

echo "Skill source: $SOURCE_DIR"
echo "Scope: $SCOPE"

for i in "${!DEDUP_PATHS[@]}"; do
  dest="${DEDUP_PATHS[$i]}"
  label="${DEDUP_LABELS[$i]}"

  if [[ $UNINSTALL -eq 1 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "[dry-run] uninstall ($label): $dest"
      continue
    fi
    if [[ -L "$dest" || -e "$dest" ]]; then
      rm -rf "$dest"
      echo "[removed] ($label) $dest"
    else
      echo "[absent]  ($label) $dest"
    fi
    continue
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    mode="copy"
    [[ $LINK_MODE -eq 1 ]] && mode="link"
    echo "[dry-run] $mode ($label): $dest"
    continue
  fi

  mkdir -p "$(dirname "$dest")"
  rm -rf "$dest"

  if [[ $LINK_MODE -eq 1 ]]; then
    ln -sfn "$SOURCE_DIR" "$dest"
    echo "[linked]  ($label) $dest -> $SOURCE_DIR"
  else
    cp -R "$SOURCE_DIR" "$dest"
    echo "[copied]  ($label) $dest"
  fi
done
