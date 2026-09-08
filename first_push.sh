#!/bin/bash

REPO_DIR="/home/ws/Desktop/RetroScope"
TOKEN_FILE="/home/ws/.retroscope_token"

if [ ! -f "$TOKEN_FILE" ]; then
    echo "Please enter your GitHub Personal Access Token:"
    read -r TOKEN
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
else
    TOKEN=$(cat "$TOKEN_FILE")
fi

cd "$REPO_DIR" || exit 1

git remote set-url origin "https://wsx-9412:${TOKEN}@github.com/wsx-9412/RetroScope.git"

git push -u origin main --force 2>&1

if [ $? -eq 0 ]; then
    echo "Push successful!"
    git config credential.helper store
else
    echo "Push failed. Please check your token."
fi
