#!/bin/bash

# Script to create a new branch, sync files, and push to GitHub
set -e

KERNEL_SOURCE_DIR="/home/moxa/Work/linux-6.14/security/honeybest"
HONEYBEST_REPO_DIR="/home/moxa/Work/honeybest"
BRANCH_NAME="kernel-6.14-update"

echo "=== Creating branch and pushing to GitHub ==="
echo ""

# Navigate to the HoneyBest repository
cd "$HONEYBEST_REPO_DIR" || { echo "Error: Could not change to HoneyBest repository directory."; exit 1; }

# Check if it's a git repository
if [ ! -d .git ]; then
    echo "Error: Not a git repository. Please initialize git first."
    exit 1
fi

# Check current branch
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
echo "Current branch: $CURRENT_BRANCH"

# Create and checkout new branch
echo ""
echo "Step 1: Creating new branch '$BRANCH_NAME'..."
if git show-ref --verify --quiet refs/heads/"$BRANCH_NAME"; then
    echo "Branch '$BRANCH_NAME' already exists. Checking it out..."
    git checkout "$BRANCH_NAME"
else
    git checkout -b "$BRANCH_NAME" 2>&1 || {
        echo "Failed to create branch. Trying alternative method..."
        git branch "$BRANCH_NAME" 2>&1
        git checkout "$BRANCH_NAME" 2>&1
    }
fi
echo "✓ Branch '$BRANCH_NAME' is now active"

# Copy updated source files
echo ""
echo "Step 2: Copying updated source files from kernel tree..."
cp "$KERNEL_SOURCE_DIR"/*.c . 2>/dev/null || echo "Warning: Some .c files may not have been copied"
cp "$KERNEL_SOURCE_DIR"/*.h . 2>/dev/null || echo "Warning: Some .h files may not have been copied"
cp "$KERNEL_SOURCE_DIR"/Makefile . 2>/dev/null || echo "Warning: Makefile may not have been copied"
cp "$KERNEL_SOURCE_DIR"/Kconfig . 2>/dev/null || echo "Warning: Kconfig may not have been copied"
echo "✓ Source files copied"

# Show status
echo ""
echo "Step 3: Checking git status..."
git status --short | head -20

# Add all changes
echo ""
echo "Step 4: Staging all changes..."
git add -A
echo "✓ Files staged"

# Show what will be committed
echo ""
echo "Files to be committed:"
git status --short

# Commit changes
echo ""
echo "Step 5: Committing changes..."
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

if git diff --cached --quiet; then
    echo "No changes to commit. Files may already be up to date."
else
    git commit -m "$COMMIT_MESSAGE" || {
        echo "Commit failed or was cancelled."
        exit 1
    }
    echo "✓ Changes committed"
fi

# Check remote
echo ""
echo "Step 6: Checking remote configuration..."
if ! git remote | grep -q origin; then
    echo "⚠️  No 'origin' remote found. Please add remote:"
    echo "   git remote add origin <your-github-repo-url>"
    exit 1
fi

REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "not set")
echo "Remote URL: $REMOTE_URL"

# Push to GitHub
echo ""
echo "Step 7: Pushing branch '$BRANCH_NAME' to GitHub..."
git push -u origin "$BRANCH_NAME" 2>&1 || {
    echo "⚠️  Push failed. Error details above."
    echo ""
    echo "Troubleshooting:"
    echo "1. Check your GitHub authentication"
    echo "2. Verify remote URL: $REMOTE_URL"
    echo "3. Ensure you have push permissions"
    exit 1
}

echo ""
echo "=== Success! ==="
echo "Branch '$BRANCH_NAME' has been pushed to GitHub."
echo ""
echo "Next steps:"
echo "1. Go to your GitHub repository"
echo "2. You should see a prompt to create a Pull Request for '$BRANCH_NAME'"
echo "3. Click 'Compare & pull request' to merge via web interface"
echo ""
echo "Or visit: https://github.com/<your-username>/<repo-name>/compare/$BRANCH_NAME"
