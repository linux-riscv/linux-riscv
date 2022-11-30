#!/bin/bash

set -e

ID=`date +%Y%m%d.%H%M`
NEXT_BRANCH="dev/tjeznach/next/${ID}"

TAG_BASE="v6.1-rc7"
TAG_NEXT="tjeznach/rivos-next"

COMPONENTS=( \
    'origin/dev/bend/rivos-v6.1-rc3/feature/rivos-main' \
    'avpatel-linux/riscv_kvm_aia_v1' \
    'origin/dev/tjeznach/feature/riscv-iommu' \
    'origin/dev/tjeznach/feature/qemu-edu' \
    'origin/dev/tjeznach/feature/dpa' \
    'origin/dev/bend/feature/dce' \
)

# Checkout new merge branch based on current 'next' tag.
git checkout -b "${NEXT_BRANCH}" "${TAG_BASE}"

# Report an error and drop local integration branch.
die() {
    echo "Integraion branch '${NEXT_BRANCH}' creation failed."
    git branch -D "${NEXT_BRANCH}"
    exit 1
}

trap die ERR

# Merge feature tags
for C in ${COMPONENTS[@]}; do
    git merge -m "RIVOS: merge ${C} into ${NEXT_BRANCH}" --log=100 "${C}"
done

git tag -fa -m "Automerge for ${NEXT_BRANCH}" "${TAG_NEXT}" 
git push origin :refs/tags/${TAG_NEXT}
git push origin HEAD --tags

TAG_HASH=`git rev-parse HEAD`

echo "Integration branch ready for testing"
echo " branch    ${NEXT_BRANCH}"
echo " commit    ${TAG_HASH}"
echo " tag       ${TAG_NEXT}"
echo " based on  ${TAG_BASE}"

true
