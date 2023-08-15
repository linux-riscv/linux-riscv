# Make sure the linear mapping is mapped using PUD/P4D/PGD hugepages
def test_main(c):
    c.put("tests/all/linear_mapping_hugepages/kernel_page_table.py")
    c.sudo("python3 kernel_page_table.py")

test_main(c)
