# Make sure the libhugetlbfs test suite passes
def test_main(c):
    c.put("tests/all/svnapot/0003-Disable-hugepage-backed-malloc-if-__morecore-is-not-.patch")
    c.put("tests/all/svnapot/build_and_test.sh")

    res = c.sudo("bash build_and_test.sh")

    # make check results for 6.3
    expected_result = """
*                      64K           2M
*                      32-bit 64-bit 32-bit 64-bit
*     Total testcases:     0     53      0     93
*             Skipped:     0      1      0      9
*                PASS:     0     51      0     69
*                FAIL:     0      1      0      8
*    Killed by signal:     0      0      0      7
*   Bad configuration:     0      0      0      0
*       Expected FAIL:     0      0      0      0
*     Unexpected PASS:     0      0      0      0
*    Test not present:     0      0      0      0
* Strange test result:     0      0      0      0
"""

    res_no_trailing = ""
    for line in res.stdout.splitlines():
        res_no_trailing += line.rstrip() + "\n"

    if expected_result not in res_no_trailing:
        print("ERROR: result differs from expected")
        print("Expected: {}".format(expected_result))
        sys.exit(1)

test_main(c)
