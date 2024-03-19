import sys

check = False
with open("/sys/kernel/debug/kernel_page_tables") as f:
    lines = f.readlines()
    for line in lines:
        if "---[ Kernel mapping ]---" in line:
            check = True
            continue

        if check:
            print("First kernel mapping: {}".format(line))
            if line.startswith("0xffffffff80000000"):
                print("ERROR: Kernel is not randomized")
                sys.exit(1)
            break

sys.exit(0)
