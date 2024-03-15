#!/bin/bash

set -e

# sync current branch to tag $1
sync() {
    local tag="$1"
    local tot=$(git rev-parse --abbrev-ref HEAD)
    git merge -s ours ${tag} --no-edit --stat --log=200
    git checkout --detach ${tag}
    git reset --soft ${tot}
    git checkout ${tot}
    git commit --amend -C HEAD
}

# assuming rivos remote repo points to Rivos Inc GITLAB
git fetch -p rivos
git checkout rivos/main
git reset --hard rivos/rivos/main

latest=""

for tag in $*; do
  sync ${tag}
  latest=${tag}
done

# Rename branch for merge push
if [[ -n "${latest}" ]]; then
  git branch -m rivos/main dev/rivos/merge/${tag}
fi

echo "Push merge request:"
echo "  git push rivos"
