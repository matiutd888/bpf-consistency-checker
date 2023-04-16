#!/bin/bash

# Change to the local repository directory
cd ~/studia-current/zso/zso-2

# Get the timestamp of the last commit
last_commit_time=$(git log -1 --format=%ct)

# Find all files changed since the last commit
changed_files=$(git diff --name-only HEAD@{$last_commit_time}..HEAD)

# Send the changed files to the remote server using scp
scp $changed_files user@server:zso-2/

