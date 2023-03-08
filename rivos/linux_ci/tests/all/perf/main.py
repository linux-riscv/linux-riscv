def test_main(c, kernel_version):
    res = c.run("test -d /opt/sources/linux/Makefile || true")
    if res.exited:
        print("No linux sources found")
        return

    # Compile the libperf (shared with the host via a virtio device)
    c.sudo("bash -c 'cd /opt/sources/linux/tools/lib/perf && make'")

    # Compile the test
    c.put("tests/all/perf/test_perf_mmap.c")
    c.run("gcc -I/opt/sources/linux/tools/lib/perf/include test_perf_mmap.c -o test_perf_mmap -lperf -L/opt/sources/linux/tools/lib/perf/ -g")

    # Run the test
    c.put("tests/all/perf/run.sh")
    res = c.sudo("bash run.sh 2>&1")

    nr_user_access = 0

    # Check stdout
    for line in res.stdout.splitlines():
        if "*** User access" in line:
            nr_user_access = 0
        elif "*** No user access" in line:
            # User access was executed before, so make sure it worked
            if nr_user_access != 2:
                print("User access failed with {} user accesses".format(nr_user_access))
                sys.exit(1)
            else:
                print("SUCCESS: User access")
            nr_user_access = 0
        elif "*** Legacy" in line:
            # No user access was executed before, so make sure it worked
            if nr_user_access:
                print("No user access failed with {} user accesses".format(nr_user_access))
                sys.exit(1)
            else:
                print("SUCCESS: No user access")
            nr_user_access = 0
        elif "user access granted" in line:
            nr_user_access = nr_user_access + 1

    # Legacy access was executed before, so make sure it worked
    if nr_user_access != 1:
        print("Legacy access failed with {} user accesses".format(nr_user_access))
        sys.exit(1)
    else:
        print("SUCCESS: Legacy access")

test_main(c, kernel_version)
