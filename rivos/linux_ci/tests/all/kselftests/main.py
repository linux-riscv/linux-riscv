def test_main(c, long_valid):
    # the whole testsuite is pre-built in the image.
    def long_kselftests(c):
        res = c.sudo("bash -c 'cd /opt/kselftests && ./run_kselftest.sh -s' || true")
        # TODO do something with the results output.log :)
        return

    def short_kselftests(c):
        ref_results = """
ok 1 selftests: riscv: hwprobe
ok 2 selftests: riscv: vstate_prctl
ok 3 selftests: riscv: v_initval_nolibc
ok 4 selftests: riscv: run_mmap.sh
"""
        # the short valid only targets the riscv subdirectory and is rebuilt (the
        # idea is that generic kselftests should be updated from time to time
        # whereas riscv tests are built against the current linux tree.
        res = c.sudo("bash -c 'cd /opt/sources/linux && make ARCH=riscv O=build_kselftests defconfig && make ARCH=riscv TARGETS=riscv O=build_kselftests kselftest-install -j8'")
        res = c.sudo("bash -c /opt/sources/linux/build_kselftests/kselftest/kselftest_install/run_kselftest.sh -s > short_results.txt")
        res = c.sudo("cat short_results.txt | grep -a -E \"^TEST|^ok|^not ok\"")

        res_no_trailing = "\n"
        for line in res.stdout.splitlines():
            res_no_trailing += line.rstrip() + "\n"

        if ref_results not in res_no_trailing:
            print("* expected: {}".format(ref_results))
            print("* result: {}".format(res_no_trailing))
            raise RuntimeError("FAIL: kselftests failed")

    if long_valid:
        long_kselftests(c)
    else:
        short_kselftests(c)

test_main(c, long_valid)
