def test_main(c):
    # KASAN_MODULE_TEST
    # The insertion will fail with EAGAIN, so make sure fabric does not return.
    c.sudo("modprobe kasan_test_module || true")
    res = c.sudo("dmesg -c")

    # result strings must be matched in this order
    kasan_module_expected = [
        # The 2 first tests give rise to a "Buffer overflow detected"
        # before any access to kasan shadow memory; so comment them
        # for now.
        #".*kasan test: copy_user_test out-of-bounds in copy_from_user()",
        #".*BUG: KASAN: slab-out-of-bounds in _copy_from_user",

        #".*kasan test: copy_user_test out-of-bounds in copy_to_user()",
        #".*BUG: KASAN: slab-out-of-bounds in _copy_to_user",

        ".*kasan test: copy_user_test out-of-bounds in __copy_from_user()",
        ".*BUG: KASAN: slab-out-of-bounds in copy_user_test",

        ".*kasan test: copy_user_test out-of-bounds in __copy_to_user()",
        ".*BUG: KASAN: slab-out-of-bounds in copy_user_test",

        ".*kasan test: copy_user_test out-of-bounds in __copy_from_user_inatomic()",
        ".*BUG: KASAN: slab-out-of-bounds in copy_user_test",

        ".*kasan test: copy_user_test out-of-bounds in __copy_to_user_inatomic()",
        ".*BUG: KASAN: slab-out-of-bounds in copy_user_test",

        ".*kasan test: copy_user_test out-of-bounds in strncpy_from_user()",
        ".*BUG: KASAN: slab-out-of-bounds in strncpy_from_user",

        # Those tests were moved to KUnit tests, which explains the +2
        # in tests there.
        #".*kasan test: kasan_rcu_uaf use-after-free in kasan_rcu_reclaim",
        #".*kasan test: kasan_workqueue_uaf use-after-free on workqueue",
        #".*BUG: KASAN: use-after-free in kasan_workqueue_uaf",
        #".*BUG: KASAN: use-after-free in kasan_rcu_reclaim",
    ]

    idx = 0

    for line in res.stdout.splitlines():
        if re.match(kasan_module_expected[idx], line):
            idx = idx + 1

        if idx == len(kasan_module_expected):
            return

    raise RuntimeError("FAIL: KASAN_MODULE_TEST results differ (matched only {}/{})".format(idx, len(kasan_module_expected)))

test_main(c)
