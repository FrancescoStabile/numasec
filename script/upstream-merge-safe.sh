#!/usr/bin/env bash
set -euo pipefail

# upstream-merge-safe.sh — Auto cherry-pick Safe Zone upstream changes
#
# Safe Zone directories (zero numasec modifications):
#   src/provider/  src/auth/  src/effect/  src/id/  src/format/
#   src/bus/  src/env/  packages/ui/  packages/plugin/
#
# Usage:
#   ./script/upstream-merge-safe.sh          # dry-run (default)
#   ./script/upstream-merge-safe.sh --apply  # actually cherry-pick

SAFE_ZONE_PATTERNS=(
  "packages/numasec/src/provider/"
  "packages/numasec/src/auth/"
  "packages/numasec/src/effect/"
  "packages/numasec/src/id/"
  "packages/numasec/src/format/"
  "packages/numasec/src/bus/"
  "packages/numasec/src/env/"
  "packages/ui/"
  "packages/plugin/"
)

DIVERGED_ZONE_PATTERNS=(
  "packages/numasec/src/tool/"
  "packages/numasec/src/agent/"
  "packages/numasec/src/session/prompt/"
  "packages/numasec/src/command/"
  "packages/numasec/src/bridge/"
  "packages/numasec/src/lsp/"
  "packages/numasec/src/ide/"
  "packages/numasec/src/worktree/"
)

DRY_RUN=true
if [[ "${1:-}" == "--apply" ]]; then
  DRY_RUN=false
fi

cd "$(git rev-parse --show-toplevel)/agent"

echo "=== Numasec Upstream Safe Zone Merge ==="
echo ""

# Ensure upstream remote exists
if ! git remote get-url upstream &>/dev/null; then
  echo "Adding upstream remote..."
  git remote add upstream https://github.com/sst/opencode.git
fi

echo "Fetching upstream..."
git fetch upstream main --quiet

MERGE_BASE=$(git merge-base HEAD upstream/main 2>/dev/null || echo "")
if [[ -z "$MERGE_BASE" ]]; then
  echo "ERROR: Cannot find merge base with upstream. Aborting."
  exit 1
fi

echo "Merge base: $MERGE_BASE"
echo ""

# Get all new upstream commits
mapfile -t ALL_COMMITS < <(git log --format="%H" "${MERGE_BASE}..upstream/main" --reverse)
echo "Total upstream commits since merge base: ${#ALL_COMMITS[@]}"

if [[ ${#ALL_COMMITS[@]} -eq 0 ]]; then
  echo "No new upstream commits. Nothing to do."
  exit 0
fi

# Filter: find commits that ONLY touch Safe Zone files
SAFE_COMMITS=()
REVIEW_COMMITS=()
SKIPPED_COMMITS=()

for commit in "${ALL_COMMITS[@]}"; do
  files_changed=$(git diff-tree --no-commit-id --name-only -r "$commit")
  all_safe=true
  any_diverged=false

  for file in $files_changed; do
    in_safe=false
    for pattern in "${SAFE_ZONE_PATTERNS[@]}"; do
      if [[ "$file" == "$pattern"* ]]; then
        in_safe=true
        break
      fi
    done

    if ! $in_safe; then
      all_safe=false
    fi

    for pattern in "${DIVERGED_ZONE_PATTERNS[@]}"; do
      if [[ "$file" == "$pattern"* ]]; then
        any_diverged=true
        break
      fi
    done
  done

  if $any_diverged; then
    SKIPPED_COMMITS+=("$commit")
  elif $all_safe; then
    SAFE_COMMITS+=("$commit")
  else
    REVIEW_COMMITS+=("$commit")
  fi
done

echo ""
echo "=== Zone Classification ==="
echo "  Safe (auto-mergeable):   ${#SAFE_COMMITS[@]}"
echo "  Review (manual):         ${#REVIEW_COMMITS[@]}"
echo "  Diverged (skip):         ${#SKIPPED_COMMITS[@]}"
echo ""

if [[ ${#SAFE_COMMITS[@]} -eq 0 ]]; then
  echo "No safe-zone-only commits found."
  echo ""
  if [[ ${#REVIEW_COMMITS[@]} -gt 0 ]]; then
    echo "Review Zone commits (manual cherry-pick needed):"
    for commit in "${REVIEW_COMMITS[@]}"; do
      msg=$(git log --format="%h %s" -1 "$commit")
      echo "  $msg"
    done
  fi
  exit 0
fi

echo "Safe Zone commits to cherry-pick:"
for commit in "${SAFE_COMMITS[@]}"; do
  msg=$(git log --format="%h %s" -1 "$commit")
  echo "  $msg"
done
echo ""

if $DRY_RUN; then
  echo "[DRY RUN] Would cherry-pick ${#SAFE_COMMITS[@]} commits."
  echo "Run with --apply to execute."
  echo ""

  if [[ ${#REVIEW_COMMITS[@]} -gt 0 ]]; then
    echo "Review Zone commits (manual cherry-pick needed):"
    for commit in "${REVIEW_COMMITS[@]}"; do
      msg=$(git log --format="%h %s" -1 "$commit")
      files=$(git diff-tree --no-commit-id --name-only -r "$commit" | head -5)
      echo "  $msg"
      echo "    Files: $(echo "$files" | tr '\n' ', ')"
    done
  fi
  exit 0
fi

# Create a branch for the merge
BRANCH="upstream-safe-$(date +%Y-%m-%d)"
echo "Creating branch: $BRANCH"
git checkout -b "$BRANCH"

APPLIED=0
FAILED=0

for commit in "${SAFE_COMMITS[@]}"; do
  msg=$(git log --format="%h %s" -1 "$commit")
  if git cherry-pick -x "$commit" --no-edit 2>/dev/null; then
    echo "  ✅ $msg"
    ((APPLIED++))
  else
    echo "  ❌ $msg (conflict — aborting cherry-pick)"
    git cherry-pick --abort 2>/dev/null || true
    ((FAILED++))
  fi
done

echo ""
echo "=== Results ==="
echo "  Applied: $APPLIED"
echo "  Failed:  $FAILED"
echo ""

if [[ $APPLIED -gt 0 ]]; then
  echo "Running typecheck..."
  if bun typecheck 2>/dev/null; then
    echo "  ✅ Typecheck passed"
  else
    echo "  ❌ Typecheck failed — review changes before merging"
  fi

  echo ""
  echo "Branch '$BRANCH' ready. Create a PR:"
  echo "  git push origin $BRANCH"
  echo "  gh pr create --title 'upstream: safe zone sync $(date +%Y-%m-%d)' --body 'Auto cherry-picked $APPLIED safe-zone commits from upstream OpenCode.'"
fi
