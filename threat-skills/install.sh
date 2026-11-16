#!/usr/bin/env bash
# Install the threat-modeling skills into a project repo for one or more coding agents.
#
# Usage: ./install.sh [options] /path/to/repo
#
# Options:
#   -a, --agents LIST   Comma-separated agents, or "all" (default: all).
#                       Supported: claude, codex, copilot, cline, opencode, kiro, pi
#   -c, --copy          Real copies in every folder (Windows, or tools that don't follow symlinks).
#                       Default: one real copy in the first selected folder, symlinks for the rest.
#   -u, --uninstall     Remove the skills from the selected agent folders.
#   -n, --dry-run       Print what would happen without changing anything.
#   -l, --list          List supported agents and their skill folders, then exit.
#   -h, --help          Show this help.
#
# Examples:
#   ./install.sh ~/work/my-service                       # all agents
#   ./install.sh -a claude,kiro ~/work/my-service        # only these two
#   ./install.sh -a codex,copilot --copy ~/work/my-service
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
SKILLS_SRC="$SRC/skills"
SKILLS="threat-model-draft threat-to-requirements threat-check"

# agent -> project-relative skills folder (must stay exactly two path levels deep:
# the relative symlinks below rely on it).
agent_dir() {
  case "$1" in
    claude)   echo ".claude/skills" ;;
    codex)    echo ".agents/skills" ;;     # also read by OpenCode, Cline, Pi and others
    copilot)  echo ".github/skills" ;;
    cline)    echo ".cline/skills" ;;
    opencode) echo ".opencode/skills" ;;
    kiro)     echo ".kiro/skills" ;;
    pi)       echo ".pi/skills" ;;
    *) return 1 ;;
  esac
}
ALL_AGENTS="claude codex copilot cline opencode kiro pi"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "error: $*" >&2; exit 1; }

AGENTS="all"; COPY=0; UNINSTALL=0; DRY=0; REPO=""
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--agents)    [ $# -ge 2 ] || die "$1 needs a value"; AGENTS="$2"; shift 2 ;;
    --agents=*)     AGENTS="${1#*=}"; shift ;;
    -c|--copy)      COPY=1; shift ;;
    -u|--uninstall) UNINSTALL=1; shift ;;
    -n|--dry-run)   DRY=1; shift ;;
    -l|--list)      for a in $ALL_AGENTS; do printf '%-9s %s\n' "$a" "$(agent_dir "$a")"; done; exit 0 ;;
    -h|--help)      usage; exit 0 ;;
    -*)             die "unknown option: $1 (try --help)" ;;
    *)              [ -z "$REPO" ] || die "more than one repo path given"; REPO="$1"; shift ;;
  esac
done
[ -n "$REPO" ] || { usage >&2; exit 2; }
[ -d "$REPO" ] || die "repo path does not exist: $REPO"
REPO="$(cd "$REPO" && pwd)"
for s in $SKILLS; do [ -f "$SKILLS_SRC/$s/SKILL.md" ] || die "missing source skill: $SKILLS_SRC/$s"; done

# Resolve the agent list to a de-duplicated list of folders (codex-style shared folders appear once).
[ "$AGENTS" = "all" ] && AGENTS="${ALL_AGENTS// /,}"
DIRS=""; NAMES=""
IFS=',' read -r -a WANT <<< "$AGENTS"
for a in "${WANT[@]}"; do
  a="$(echo "$a" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
  [ -n "$a" ] || continue
  d="$(agent_dir "$a")" || die "unsupported agent: $a (supported: $ALL_AGENTS)"
  case " $DIRS " in *" $d "*) ;; *) DIRS="$DIRS $d" ;; esac
  NAMES="$NAMES $a"
done
[ -n "$DIRS" ] || die "no agents selected"

run() { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }

if [ "$UNINSTALL" = 1 ]; then
  for d in $DIRS; do
    for s in $SKILLS; do
      [ -e "$REPO/$d/$s" ] || [ -L "$REPO/$d/$s" ] || continue
      run rm -rf "$REPO/$d/$s"; echo "removed $d/$s"
    done
    # drop the folder (and its parent) only when we left it empty
    [ "$DRY" = 1 ] || { rmdir "$REPO/$d" 2>/dev/null && rmdir "$(dirname "$REPO/$d")" 2>/dev/null || true; }
  done
  echo "Uninstalled for:$NAMES. threat-model/ (your models and config) was left untouched."
  exit 0
fi

# First folder holds the real copy; the others link to it unless --copy.
CANON=""
for d in $DIRS; do
  if [ -z "$CANON" ]; then
    CANON="$d"
    run mkdir -p "$REPO/$d"
    for s in $SKILLS; do run rm -rf "$REPO/$d/$s"; run cp -R "$SKILLS_SRC/$s" "$REPO/$d/$s"; done
    echo "installed (copy)    $d"
  else
    run mkdir -p "$REPO/$d"
    for s in $SKILLS; do
      run rm -rf "$REPO/$d/$s"
      if [ "$COPY" = 1 ]; then
        run cp -R "$SKILLS_SRC/$s" "$REPO/$d/$s"
      else
        run ln -s "../../$CANON/$s" "$REPO/$d/$s"
      fi
    done
    if [ "$COPY" = 1 ]; then echo "installed (copy)    $d"; else echo "installed (symlink) $d -> $CANON"; fi
  fi
done

# Per-project config: never overwrite an existing one.
run mkdir -p "$REPO/threat-model"
if [ -f "$REPO/threat-model/config.json" ]; then
  echo "kept existing threat-model/config.json"
else
  run cp "$SRC/config.example.json" "$REPO/threat-model/config.json"
  echo "created threat-model/config.json"
fi

echo
echo "Done for:$NAMES"
echo "Commit these folders so the whole team uses the same skill version."
