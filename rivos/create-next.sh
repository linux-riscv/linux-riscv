#!/bin/bash

#
# Rivos kernel merge script.
#
# Run from Linux git repository with remote branches pointing to:
# - git remote add rivos    https://gitlab.ba.rivosinc.com/rv/sw/ext/linux.git
#
# Repositories used for 3rd party patches
# - git remote add avpatel  https://github.com/avpatel/linux.git
# - git remote add vlsunil  https://github.com/vlsunil/linux.git
#
# Use upstream tag and optional dot-release, eg. target rivos/next/v6.6-rc2.1:
# $ rivos/create-next -u v6.6-rc2 -d 1
#
# After successful merge, test locally and push release candidate branch:
#  git push rivos
#
# If needed, re-generate candidate branch, re-test.
#
# After test completes successfully annotate with release tag and push:
#  git tag -a ${TAG} -m 'Rivos Linux ${VER}'
#  git push --follow-tags rivos
#

set -e

VER=v6.7-rc5
DOT=
ORG="rivos"
INTERNAL=true
TAG_PREFIX=

while getopts 'u:d:o:eklh' opt; do
  case "$opt" in
  u)
    echo "Upstream tag: $OPTARG"
    VER="$OPTARG"
    ;;
  d)
    echo "Dot release: $OPTARG"
    DOT="$OPTARG"
    ;;
  e)
    echo "Merge for external consumption"
    INTERNAL=false
    TAG_PREFIX="external-"
    ;;
  o)
    echo "Origin repo: $OPTARG"
    ORG="$OPTARG"
    ;;
  l)
    echo "Using local branches"
    local_src=
    ;;
  k)
    echo "Keep current branch state"
    no_reset=yes
    ;;
  h|?)
    echo "Usage: $(basename $0) [-u upstream-tag] [-d dot-release] [-o origin] [-l] [-k]"
    echo "  -l  - use local repository as source"
    echo "  -k  - keep current branch state, do not reset to the upstream tag"
    exit 0
    ;;
  esac
done

DST="dev/rivos/next/${TAG_PREFIX}${VER}${DOT:+.$DOT}"
TAG="rivos/${TAG_PREFIX}${VER}${DOT:+.$DOT}"
SRC="${local_src-${ORG:+$ORG/}}"

GIT_MERGE="git merge --no-ff --log=100 --stat --no-edit --signoff"

# Fetch latest remotes
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
if [[ "${INTERNAL}" == "true" ]]; then
  ${GIT_MERGE} "${SRC}dev/rivos/topic/rivos_main"
fi

# Ventana public patch series
# 1. based on avpatel/riscv_aia_v* (KVM, SBI-DBCN, AIA)
${GIT_MERGE} "${SRC}dev/rivos/topic/riscv_aia_v12"
# 2. based on vlsunil/riscv_acpi_* (ACPI)
${GIT_MERGE} "${SRC}dev/rivos/topic/riscv_acpi_aia_v12"

# Rivos patch series
# Maintainer: @tjeznach
${GIT_MERGE} "${SRC}dev/rivos/topic/riscv_iommu_v2"
if [[ "${INTERNAL}" == "true" ]]; then
  # Maintainer: @tjeznach
  ${GIT_MERGE} "${SRC}dev/tjeznach/feature/qemu-edu"
  # Maintainer: @bend
  ${GIT_MERGE} "${SRC}dev/bend/feature/dce"
  # Maintainer: @sonny
  ${GIT_MERGE} "${SRC}dev/sonny/feature/dpa"
  # Maintainer: @evan
  ${GIT_MERGE} "${SRC}dev/evan/isbdm"
  # Maintainer: @tjeznach
  ${GIT_MERGE} "${SRC}dev/rivos/topic/rivos_pci"
  # Maintainer: @cleger
  ${GIT_MERGE} "${SRC}dev/rivos/topic/rivos_hwmon"
  # Maintainer: @charlie
  ${GIT_MERGE} "${SRC}dev/rivos/topic/rivos_emulation"
fi
# Maintainer: @mnissler
${GIT_MERGE} "${SRC}dev/mnissler/feature/pcs_stub"
# Maintainer: @abrestic
${GIT_MERGE} "${SRC}dev/rivos/topic/memory_hotplug"

# After successful merge and test create rivos release tag:
echo "Apply tag and push to RIVOS repository when tested:"
echo "  git tag -a ${TAG} -m 'Rivos Linux ${VER}'"
echo "  git push --follow-tags rivos"
