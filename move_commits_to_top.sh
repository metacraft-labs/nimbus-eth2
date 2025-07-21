#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <commit-message-prefix>"
  exit 1
fi

prefix="$1"

# Get all commits on current branch, oldest first
commits=($(git rev-list --reverse HEAD))

matching_commits=()
non_matching_commits=()

# Separate commits based on prefix
for c in "${commits[@]}"; do
  msg=$(git log -1 --pretty=%s "$c")  # Use %s for first line of commit message
  if [[ "$msg" == "$prefix"* ]]; then
    matching_commits+=("$c")
  else
    non_matching_commits+=("$c")
  fi
done

if [ "${#matching_commits[@]}" -eq 0 ]; then
  echo "No commits found with prefix: '$prefix'"
  exit 1
fi

echo "Found ${#matching_commits[@]} matching commits with prefix '$prefix':"
for c in "${matching_commits[@]}"; do
  echo "  - $c $(git log -1 --oneline $c)"
done

# Build new commit order:
# 1) Non-matching commits in original order
# 2) Then all matching commits in original order (to be squashed)

new_order=("${non_matching_commits[@]}" "${matching_commits[@]}")

count=${#commits[@]}

todo_file=$(mktemp)

# Write pick lines for non-matching commits
for c in "${non_matching_commits[@]}"; do
  echo "pick $c" >> "$todo_file"
done

# For matching commits:
# The first one should be 'pick', the rest should be 'squash'
first=true
for c in "${matching_commits[@]}"; do
  if $first; then
    echo "pick $c" >> "$todo_file"
    first=false
  else
    echo "squash $c" >> "$todo_file"
  fi
done

echo "Rebasing to move matching commits to top and squash them..."

# Determine upstream for rebase
if [ "$count" -eq 1 ]; then
  echo "Only one commit in branch, nothing to reorder."
  rm "$todo_file"
  exit 0
fi

if git rev-parse "HEAD~$count" >/dev/null 2>&1; then
  upstream="HEAD~$count"
else
  upstream="--root"
fi

GIT_SEQUENCE_EDITOR="cat $todo_file >" git rebase -i $upstream

rm "$todo_file"
