#!/bin/bash
set -euo pipefail

echo "=== OpenClaw-Hardened Local Verification ==="
echo ""
echo "This script verifies the security modules build and pass tests locally."
echo "Copy the terminal output to prove the code works on your machine."
echo ""

# Step 1: Clean install
echo "[1/4] Clean dependency install..."
if [ -d "node_modules" ]; then
  echo "  → Removing existing node_modules..."
  rm -rf node_modules
fi
pnpm install --frozen-lockfile
echo "  ✓ Dependencies installed"
echo ""

# Step 2: Build project
echo "[2/4] Building TypeScript..."
pnpm build
echo "  ✓ Build successful"
echo ""

# Step 3: Run security module tests
echo "[3/4] Running security tests..."
pnpm exec vitest run src/security/ --reporter=verbose
echo "  ✓ Security tests passed"
echo ""

# Step 4: Check coverage
echo "[4/4] Generating coverage report..."
pnpm exec vitest run src/security/ --coverage --reporter=verbose
echo "  ✓ Coverage report generated"
echo ""

echo "=== Verification Complete ==="
echo ""
echo "All security modules built and tested successfully."
echo "Coverage report available in: coverage/index.html"
