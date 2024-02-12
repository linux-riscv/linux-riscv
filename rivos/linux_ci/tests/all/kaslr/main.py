# Read the kernel page table and make sure the kernel mapping is offseted
# (it may happen it is not, ie seed == 0, but I doubt it)
def test_main(c):
    c.put("tests/all/kaslr/kernel_page_table.py")
    c.sudo("python3 kernel_page_table.py")

test_main(c)
