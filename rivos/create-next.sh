#!/bin/bash

#
# Rivos kernel merge script.
#
# Run from Linux git repository with remote branches pointing to:
# - git remote add avpatel https://github.com/avpatel/linux.git
# - git remote add rivos https://gitlab.ba.rivosinc.com/rv/sw/ext/linux.git
#
# Use upstream tag and optional dot-release, eg. target rivos/next/v6.3-rc1.1:
# $ rivos/create-next -u v6.3-rc1 -d 1
#
# After successful merge, test locally and push release candidate branch:
#  git push rivos
#
# After test completes successfully annotate with release tag and push:
#  git tag -a ${TAG} -m 'Rivos Linux ${VER}'
#  git push --follow-tags rivos
#

set -e

VER=v6.4-rc7
DOT=
ORG="rivos"

while getopts 'u:d:o:kh' opt; do
  case "$opt" in
  u)
    echo "Upstream tag: $OPTARG"
    VER="$OPTARG"
    ;;
  d)
    echo "Dot release: $OPTARG"
    DOT="$OPTARG"
    ;;
  o)
    echo "Origin repo: $OPTARG"
    ORG="$OPTARG"
    ;;
  k)
    echo "Keep current branch state"
    no_reset=yes
    ;;
  h|?)
    echo "Usage: $(basename $0) [-u upstream-tag] [-d dot-release] [-o origin]"
    exit 0
    ;;
  esac
done

DST="dev/rivos/next/${VER}${DOT:+.$DOT}"
TAG="rivos/${VER}${DOT:+.$DOT}"
SRC="${ORG:+$ORG/}"

GIT_MERGE="git merge --no-ff --log=100 --stat --no-edit --signoff"

# Fetch latest remotes
git fetch -p avpatel
git fetch -p "$ORG"

# Check target branch reference, local
if git show-ref --quiet refs/heads/${DST}; then
  read -t 10 -p "Target branch ${DST} exists in local repository, reset [y/N] " YN
  test "${YN}" == "${YN#[Yy]}" && exit 1
  git checkout "${DST}"
else
  git checkout -b "${DST}"
fi

if [[ $(git ls-remote --exit-code --heads rivos "${DST}") ]]; then
  read -t 10 -p "Target branch ${DST} exists in remote '${ORG}' repository, continue [y/N] " YN
  test "${YN}" == "${YN#[Yy]}" && exit 1
fi

# Reset and re-merge all
test -z "${no_reset}" && git reset --hard ${VER}

# Rivos: Internal CI rules and unsorted private patches.
${GIT_MERGE} "${SRC}dev/tjeznach/feature/rivos-main"

# Ventana: AIA/KVM patches
${GIT_MERGE} avpatel/riscv_kvm_aia_hwaccel_v1
${GIT_MERGE} avpatel/riscv_sbi_dbcn_v1

# Rivos: private features
${GIT_MERGE} "${SRC}dev/tjeznach/feature/riscv-iommu"
${GIT_MERGE} "${SRC}dev/bend/feature/dce"
${GIT_MERGE} "${SRC}dev/sonny/feature/dpa"
${GIT_MERGE} "${SRC}dev/evan/isbdm"

# After successful merge and test create rivos release tag:
echo "Apply tag and push to RIVOS repository when tested:"
echo "  git tag -a ${TAG} -m 'Rivos Linux ${VER}'"
echo "  git push --follow-tags rivos"
