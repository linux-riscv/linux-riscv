def test_main(c, long_valid):
    # the whole testsuite is pre-built in the image.
    def long_kselftests(c):
        res = c.sudo("bash -c 'cd /opt/kselftests && ./run_kselftest.sh -s' || true")
        # TODO do something with the results output.log :)
        return

    if long_valid:
        long_kselftests(c)
    else:
        # the short valid only targets the riscv subdirectory and is rebuilt (the
        # idea is that generic kselftests should be updated from time to time
        # whereas riscv tests are built against the current linux tree.
        res = c.sudo("bash -c 'cd /opt/sources/linux && make ARCH=riscv O=build_kselftests defconfig && make ARCH=riscv TARGETS=riscv O=build_kselftests kselftest-install -j8'")
        res = c.sudo("bash -c /opt/sources/linux/build_kselftests/kselftest/kselftest_install/run_kselftest.sh -s")

test_main(c, long_valid)
