# Integration branch for fs-sim

## Recreate branch with:

Assuming remote repositories:

- origin: git@gitlab.ba.rivosinc.com:rv/sw/ext/linux.git
- avpatel-linux: https://github.com/avpatel/linux.git
- tjeznach-linux: git@github.com:tjeznach/linux.git

And feature branches:

- AIA/KVM: avpatel-linux/riscv_kvm_aia_v1
- DCE: origin/dev/bend/feature/dce
- DPA: origin/dev/tjeznach/feature/dpa
- IOMMU: tjeznach-linux/tjeznach/riscv-iommu

```shell
export TAG="v6.1-rc3"

git reset --hard ${TAG}
git merge origin/rivos/main
git merge avpatel-linux/riscv_kvm_aia_v1
git merge tjeznach-linux/tjeznach/riscv-iommu
git merge origin/dev/bend/feature/dce
git merge origin/dev/tjeznach/feature/dpa

# carry-over RIVOS.md
git checkout origin/dev/tjeznach/fs-sim/next RIVOS.md
commit -m "RIVOS: integration branch on top of ${TAG}"

# update remote (optional --force)
git push

```
