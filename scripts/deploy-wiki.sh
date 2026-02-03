#!/bin/bash
# Automates GitHub Wiki deployment for OpenClaw-Hardened
# Author: Sai Srujan Murthy A N

set -e  # Exit on error

echo "🚀 Deploying OpenClaw-Hardened Wiki..."

# Configuration
WIKI_REPO="https://github.com/Shiva-destroyer/OpenClaw-Hardened.wiki.git"
WIKI_DIR="OpenClaw-Hardened.wiki"
SOURCE_DIR="docs/wiki"

# Navigate to parent directory
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo "📂 Project root: $PROJECT_ROOT"

# Navigate to parent directory (one level up from project)
cd ..

# Clone wiki (if not exists) or pull (if exists)
if [ -d "$WIKI_DIR" ]; then
    echo "📥 Wiki repository exists. Pulling latest changes..."
    cd "$WIKI_DIR"
    git pull origin master || git pull origin main
else
    echo "📥 Cloning Wiki repository..."
    git clone "$WIKI_REPO"
    cd "$WIKI_DIR"
fi

# Copy files from the main project
echo "📂 Syncing wiki files from source..."
cp "$PROJECT_ROOT/$SOURCE_DIR"/*.md .

# Check if there are changes
if [[ -z $(git status --porcelain) ]]; then
    echo "✅ No changes detected. Wiki is already up to date."
    exit 0
fi

# Show what changed
echo "📝 Changes detected:"
git status --short

# Stage and commit changes
git add .
git commit -m "docs: Update Wiki from main repo ($(date '+%Y-%m-%d %H:%M:%S'))"

# Push changes
echo "⬆️  Pushing to GitHub Wiki..."
git push origin HEAD

echo ""
echo "✅ Wiki Deployed Successfully!"
echo "🔗 View at: https://github.com/Shiva-destroyer/OpenClaw-Hardened/wiki"
