def test_main(c):
    return

    # TODO Move that to the image creation stage when possible
    c.sudo("bash -c 'apt update && apt install libfdt-dev'")
    c.run("git clone https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git")
    c.run("cd kvmtool && ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- make lkvm-static -j$(nproc) && ${CROSS_COMPILE}strip lkvm-static")

    c.sudo("modprobe kvm")

    c.sudo("bash -c 'cd kvmtool && timeout 60 ./lkvm-static run -m 512 -c2 --console serial -p \"console=ttyS0 earlycon=uart8250,mmio,0x3f8\" -k /boot/vmlinuz --initrd /boot/initrd --debug > /tmp/kvmout' || true")

    # Let's just check we reached the userspace
    c.run("grep \"Run /init as init process\" /tmp/kvmout")

test_main(c)
