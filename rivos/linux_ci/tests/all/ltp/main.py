def test_main(c, kernel_version, long_valid):
    def ltp_get_results_file(c, kernel_version):
        c.get("/home/ubuntu/ltp_output", "tests_results/{}/ltp/ltp_output".format(kernel_version))
        c.get("/home/ubuntu/ltp_cur.log", "tests_results/{}/ltp/ltp_cur.log".format(kernel_version))
        c.get("/home/ubuntu/ltp_failed.log", "tests_results/{}/ltp/ltp_failed.log".format(kernel_version))
        c.get("/home/ubuntu/ltp_conf.log", "tests_results/{}/ltp/ltp_conf.log".format(kernel_version))

    def ltp_short_valid(c, kernel_version):
        # Only launch a small subset of tests for sanity checks, this scenario is known to succeed
        # so no need to compare the logs, let fabric stop on its own if this fails.
        res = c.sudo("LTP_TIMEOUT_MUL=10 bash -c 'cd /opt/ltp && ./runltp -o /home/ubuntu/ltp_output -l /home/ubuntu/ltp_cur.log -C /home/ubuntu/ltp_failed.log -T /home/ubuntu/ltp_conf.log -s mmap' || true")

        ltp_get_results_file(c, kernel_version)

        if "INFO: ltp-pan reported some tests FAIL" in res.stdout:
            raise RuntimeError("FAIL: LTP testsuite failed")

    # ltp comes preinstalled (very long to build...)

    if not long_valid:
        ltp_short_valid(c, kernel_version)
    else:
        res = c.sudo("LTP_TIMEOUT_MUL=10 bash -c 'cd /opt/ltp && ./runltp -o /home/ubuntu/ltp_output -l /home/ubuntu/ltp_cur.log -C /home/ubuntu/ltp_failed.log -T /home/ubuntu/ltp_conf.log {}' || true")

        ltp_get_results_file(c, kernel_version)

        with open("tests/all/ltp/ltp_ref_long_valid.log", "r") as f:
            fref_lines = f.readlines()

        with open("tests_results/{}/ltp/ltp_cur.log".format(kernel_version), "r") as f:
            fcur_lines = f.readlines()
            for line in fcur_lines[:]:
                if line.startswith("Test Start Time"):
                    break
                else:
                    fcur_lines.remove(line)

        # Discard the first line "Test Start Time" and the line starting
        # with "Kernel Version"
        results_differ = False

        for (line_ref, line_cur) in zip(fref_lines, fcur_lines):
            if line_ref.startswith("Test Start Time") or line_ref.startswith("Kernel Version"):
                continue

            if line_ref != line_cur:
                print("* diff found at:")
                print("  - ref: {}".format(line_ref.strip("\n")))
                print("  - cur: {}".format(line_cur.strip("\n")))

                results_differ = True

        if results_differ:
            raise RuntimeError("FAIL: LTP testsuite failed")

test_main(c, kernel_version, long_valid)

