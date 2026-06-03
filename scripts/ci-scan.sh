#!/usr/bin/env bash
# Itzraven CI/CD scan script
# Usage: ITZRAVEN_TARGET=./my-app ./scripts/ci-scan.sh

set -euo pipefail

TARGET="${ITZRAVEN_TARGET:-.}"
MODE="${ITZRAVEN_MODE:-pentest}"
OUTPUT="${ITZRAVEN_OUTPUT:-./itzraven_results}"
FORMAT="${ITZRAVEN_FORMAT:-sarif}"
LLM_KEY="${LLM_API_KEY:-}"

echo "=== Itzraven CI Scan ==="
echo "Target: $TARGET"
echo "Mode: $MODE"
echo "Output: $OUTPUT"
echo "Format: $FORMAT"

# Install if needed
if ! command -v itzraven &>/dev/null; then
    echo "Installing Itzraven..."
    pip install -r requirements.txt -q
    pip install -e . -q
fi

ARGS="--target $TARGET --mode $MODE --non-interactive --output $OUTPUT --format $FORMAT"

# Diff-scope for PRs
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    ARGS="$ARGS --scope-mode diff --diff-base origin/$GITHUB_BASE_REF"
fi

if [[ -n "$LLM_KEY" ]]; then
    export LLM_API_KEY="$LLM_KEY"
fi

# Run scan
itzraven strix $ARGS

echo "=== Scan Complete ==="
echo "Results in: $OUTPUT"
