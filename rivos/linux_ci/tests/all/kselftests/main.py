def test_main(c, long_valid):
    if not long_valid:
        return

    res = c.sudo("bash -c 'cd /opt/kselftests && ./run_kselftest.sh -s' || true")

    # TODO do something with the results output.log :)

test_main(c, long_valid)
