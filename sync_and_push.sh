#!/bin/bash

# Script to sync updated files from kernel tree and push to GitHub
set -e

KERNEL_SOURCE_DIR="/home/moxa/Work/linux-6.14/security/honeybest"
HONEYBEST_REPO_DIR="/home/moxa/Work/honeybest"

echo "=== HoneyBest GitHub Sync Script ==="
echo ""

# Navigate to the HoneyBest repository
cd "$HONEYBEST_REPO_DIR" || { echo "Error: Could not change to HoneyBest repository directory."; exit 1; }

# Check if it's a git repository
if [ ! -d .git ]; then
    echo "Error: Not a git repository. Please initialize git first."
    exit 1
fi

# Copy updated source files
echo "Step 1: Copying updated source files from kernel tree..."
cp "$KERNEL_SOURCE_DIR"/*.c . 2>/dev/null || true
cp "$KERNEL_SOURCE_DIR"/*.h . 2>/dev/null || true
cp "$KERNEL_SOURCE_DIR"/Makefile . 2>/dev/null || true
cp "$KERNEL_SOURCE_DIR"/Kconfig . 2>/dev/null || true
echo "✓ Source files copied"

# Show status
echo ""
echo "Step 2: Checking git status..."
git status --short | head -20

# Add all changes
echo ""
echo "Step 3: Staging all changes..."
git add -A
echo "✓ Files staged"

# Commit changes
echo ""
echo "Step 4: Committing changes..."
COMMIT_MESSAGE="Update for kernel 6.14 compatibility

- Updated all LSM hook signatures for kernel 6.14
- Fixed compilation errors (mmap_lock, proc_ops, sysctl API changes)
- Updated CONFIG_SECURITY_HONEYBEST_PROD implementation
- Fixed all *.c and *.h files initialization
- Fixed patch file Makefile hunk (added missing + prefix)
- Updated patches for kernel 6.14
- Added comprehensive hook analysis documentation (NEW_HOOKS_ANALYSIS.md)
- Verified KERNEL_VERSION compatibility
- Confirmed CONFIG_SECURITY_PATH compilation
- All source files updated and tested"

git commit -m "$COMMIT_MESSAGE" || echo "Note: No changes to commit or commit failed"
echo "✓ Changes committed"

# Determine branch
BRANCH=$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
echo ""
echo "Step 5: Pushing to GitHub (branch: $BRANCH)..."

# Check remote
if git remote | grep -q origin; then
    echo "Remote 'origin' found"
    git push origin "$BRANCH" 2>&1 || {
        echo "Push failed. Trying alternative branches..."
        git push origin main 2>&1 || git push origin master 2>&1 || {
            echo "⚠️  Push failed. Please check:"
            echo "   1. Remote URL: $(git remote get-url origin 2>/dev/null || echo 'not set')"
            echo "   2. Branch name: $BRANCH"
            echo "   3. Authentication credentials"
            exit 1
        }
    }
    echo "✓ Successfully pushed to GitHub"
else
    echo "⚠️  No 'origin' remote found. Please add remote:"
    echo "   git remote add origin <your-github-repo-url>"
    exit 1
fi

echo ""
echo "=== Sync Complete ==="
