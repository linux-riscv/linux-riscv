def test_main(c):
    c.sudo("modprobe kasan_test || true")
    res = c.sudo("dmesg -c")

    # KASAN_KUNIT_TEST
    kasan_kunit_test_expect = "# kasan: pass:35 fail:2 skip:21 total:58"
    if kasan_kunit_test_expect not in res.stdout:
        result = ""
        for line in res.stdout:
            if re.match("# kasan: pass:", line):
                result = line
                break
        raise RuntimeError("FAIL: KASAN_KUNIT_TEST results differ:\nexpected: {}\nresult: {}".format(kasan_kunit_test_expect, result))

test_main(c)
