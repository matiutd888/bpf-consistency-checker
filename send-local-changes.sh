#!/bin/bash

# Change to the local repository directory
cd ~/studia-current/zso/zso-2

# Get the timestamp of the last commit
last_commit_time=$(git log -1 --format=%ct)

# Find all files changed since the last commit
changed_files=$(git diff --name-only HEAD^)
echo $changed_files

for f in $changed_files
do
    echo $f
    scp $f zso-root:zso-2/$f
done

# Send the changed files to the remote server using scp
# scp $changed_files zso-root:zso-2/$changed_files

