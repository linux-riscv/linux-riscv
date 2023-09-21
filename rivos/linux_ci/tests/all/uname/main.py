# Make sure we are testing the right kernel
def test_main(c, kernel_version):
    res = c.run("uname -a")

    deb_kernel_version = kernel_version.replace("_", "-")

    if deb_kernel_version not in res.stdout:
        raise RuntimeError("FAIL: {} not in uname -a".format(deb_kernel_version))

test_main(c, kernel_version)
