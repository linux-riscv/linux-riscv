import sys

check = False
with open("/sys/kernel/debug/kernel_page_tables") as f:
    lines = f.readlines()
    for line in lines:
        if "---[ Linear mapping ]---" in line:
            check = True
        if "---[ Modules/BPF mapping ]---" in line:
            check = False

        if check:
            if "PUD" in line or "P4D" in line or "PGD" in line:
                sys.exit(0)

sys.exit(1)
