#!/bin/bash

# # Change to the local repository directory
# cd ~/studia-current/zso/zso-2
# 
# # Get the timestamp of the last commit
# last_commit_time=$(git log -1 --format=%ct)
# 
# # Find all files changed since the last commit
# changed_files=$(git diff --name-only HEAD)
# echo $changed_files
# 
# for f in $changed_files
# do
#     echo $f
#     rsync -ru $f zso-root:zso-2/$f
# done

# Send the changed files to the remote server using scp
# scp $changed_files zso-root:zso-2/$changed_files


function send {
rsync $1 --exclude "*.o.d" --exclude "*.o"  -rvuhP z2-tst-public zso-root:zso-2/
echo "test synced"
rsync $1 --exclude "*.o.d" --exclude "*.o" -rvuhP linux-6.2.1 zso-root:zso-2/
}

if [ "$1" = "-d" ]; then
 send "--dry-run"
else
 send
fi

