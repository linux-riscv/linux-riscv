#!/bin/bash

set -e

ID=`date +%Y%m%d.%H%M`
THIS_BRANCH=`git rev-parse --abbrev-ref HEAD`
NEXT_BRANCH="dev/tjeznach/next/${ID}"

# Override base tag with -b <tag>.
TAG_BASE="v6.1"
# Override tag name with -t <tag>.
TAG_NEXT="tjeznach/rivos-next"
# Push to remote repo if -p flag added.
GIT_PUSH=0

COMPONENTS=( \
    # RIVOS CI scripts.
    'origin/dev/tjeznach/rivos/ci' \
    # mirror of https://github.com/avpatel/linux/tree/riscv_kvm_aia_v1
    'origin/dev/tjeznach/feature/riscv-kvm-aia' \
    # mirror of https://github.com/tjeznach/linux/tree/tjeznach/riscv-iommu
    'origin/dev/tjeznach/feature/riscv-iommu' \
    # QEMU device driver: edu.
    'origin/dev/tjeznach/feature/qemu-edu' \
    # RIVOS device drivers: DPA, DCE.
    'origin/dev/sonny/feature/dpa' \
    'origin/dev/bend/feature/dce' \
)

while getopts "b:pk" arg; do
  case $arg in
  b ) TAG_BASE=$OPTARG ;;
  t ) TAG_NEXT=$OPTARG ;;
  p ) GIT_PUSH=1 ;;
  * ) echo "$0 [-b base_tag] [-p]"
      echo "  -b tag  : use tag as a merge parent"
      echo "  -p      : push merged branch to remote repo"
      exit 0
      ;;
  esac
done

# Checkout new merge branch based on current 'next' tag.
git checkout -b "${NEXT_BRANCH}" "${TAG_BASE}"

# Report an error and drop local integration branch.
die() {
    echo "Integraion branch '${NEXT_BRANCH}' creation failed."
    git log
    git checkout --force "${THIS_BRANCH}"
    git branch -D "${NEXT_BRANCH}"
    exit 1
}

trap die ERR

# Merge feature tags
for C in ${COMPONENTS[@]}; do
    git merge -m "RIVOS: merge ${C} into ${NEXT_BRANCH}" --log=100 --no-ff "${C}"
done

if [[ $GIT_PUSH -eq 1 ]]; then
  git tag -fa -m "Automerge for ${NEXT_BRANCH}" "${TAG_NEXT}"
  git push origin :refs/tags/${TAG_NEXT}
  git push origin HEAD --tags
fi

TAG_HASH=`git rev-parse HEAD`

echo "Integration branch ready for testing"
echo " branch    ${NEXT_BRANCH}"
echo " commit    ${TAG_HASH}"
echo " tag       ${TAG_NEXT}"
echo " based on  ${TAG_BASE}"

true
