#!/bin/bash

# Script to push BoltVulnScanner to GitHub

# Check if git is installed
if ! command -v git &> /dev/null
then
    echo "Git is not installed. Please install Git first."
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1
then
    echo "Initializing Git repository..."
    git init
fi

# Add all files
echo "Adding files to Git..."
git add .

# Check if there are any changes to commit
if ! git diff-index --quiet HEAD -- || git ls-files --exclude-standard --others | grep -q .
then
    echo "Committing changes..."
    git commit -m "Initial commit: BoltVulnScanner - Automated Web Vulnerability Scanner"
else
    echo "No changes to commit."
fi

# Check if GitHub CLI is installed
if command -v gh &> /dev/null
then
    echo "GitHub CLI found. Creating repository..."
    gh repo create BoltVulnScanner --public --source=. --remote=origin
    echo "Pushing to GitHub..."
    git push -u origin main
else
    echo "GitHub CLI not found. Please create a repository manually on GitHub and run:"
    echo "git remote add origin https://github.com/yourusername/BoltVulnScanner.git"
    echo "git branch -M main"
    echo "git push -u origin main"
fi

echo "Setup complete! Your BoltVulnScanner repository is ready."