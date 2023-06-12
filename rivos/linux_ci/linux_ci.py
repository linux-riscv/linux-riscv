import glob
import os
import re
import socket
import subprocess
import sys
import time
import shutil
from fabric import Connection
from paramiko import ssh_exception
from pathlib import Path
import argparse

SSH_MAX_TRIALS = 100
SSH_SLEEP_INTERVAL_SEC = 5
vm_path = "ubuntu-22.10-preinstalled-server-riscv64+unmatched.img"
qemu_cmd = "/rivos/qemu/bin/qemu-system-riscv64 -machine virt -cpu rv64,h=true,{}=on -bios fw_dynamic.elf -nographic -m 16G -smp 8 -kernel usr/lib/u-boot/qemu-riscv64_smode/uboot.elf -device virtio-net-device,netdev=net0 -netdev user,hostfwd=tcp::10022-:22,id=net0,tftp=tftp -drive file={},format=raw,if=virtio -virtfs local,path={},mount_tag=host0,security_model=passthrough,id=host0 -device virtio-rng-pci -s"
host_vm = "ubuntu@localhost:10022"
host_pwd = "ubuntu"
satp_mode_list = [ "sv39", "sv48", "sv57" ]

def parse_args():
    parser = argparse.ArgumentParser(description = 'Validate linux kernels')
    parser.add_argument("--dl-prepared-vm", default = "",
            help = 'Set the URL from where to download an already prepared Ubuntu VM (expects an xz file)')
    parser.add_argument("--only-prepare-vm", action = 'store_true',
            help = 'Prepare a VM and exits')

    parser.add_argument("--use-local-vm", action = 'store_true',
            help = 'Use the already prepared local VM and exits')

    parser.add_argument("--no-kernel-install", action = 'store_true',
            help = 'Do not install the kernels')

    parser.add_argument("--versions", default = "",
            help = 'Comma-separated list of kernel versions to test (ubuntu_defconfig, ubuntu_kasan_inline_defconfig, ubuntu_kasan_outline_defconfig)')

    parser.add_argument("--satp-valid", action = 'store_true',
            help = 'Launch the tests on all satp modes (sv39, sv48, sv57)')

    parser.add_argument("--long-valid", action = 'store_true',
            help = 'Launch the long validation (LTP and other long testsuites): by default, only a short validation is done')

    return parser.parse_args()

def launch_external_wait(cmd):
    # check = True will raise an exception if the script fails.
    result = subprocess.run(cmd, text = True, check = True)

def host_prepare_vm():
    # Prepare the VM
    print("* Preparing the VM...", end = "")
    sys.stdout.flush()
    launch_external_wait("bash prepare_vm_from_host.sh".split(" "))
    print("OK")

def host_finish_prepare_vm():
    # Prepare the VM
    print("* Finishing preparing the VM...", end = "")
    sys.stdout.flush()
    launch_external_wait("xz -z {}".format(vm_path).split(" "))
    print("OK")

def host_dl_prepared_vm():
    print("* Downloading prepared VM...", end = "")
    sys.stdout.flush()
    launch_external_wait("curl -O --header JOB-TOKEN:{} {}".format(os.environ["CI_JOB_TOKEN"], args.dl_prepared_vm).split(" "))
    launch_external_wait("xz -d {}".format(vm_path + ".xz").split(" "))
    print("OK")

def host_dl_firmware():
    print("* Downloading firmware...", end = "")
    sys.stdout.flush()
    launch_external_wait("curl -O --header JOB-TOKEN:{} https://gitlab.ba.rivosinc.com/api/v4/projects/38/packages/generic/firmwares/1/u-boot".format(os.environ["CI_JOB_TOKEN"]).split(" "))
    launch_external_wait("mkdir -p usr/lib/u-boot/qemu-riscv64_smode/".split(" "))
    launch_external_wait("mv u-boot usr/lib/u-boot/qemu-riscv64_smode/uboot.elf".split(" "))

    launch_external_wait("curl -O --header JOB-TOKEN:{} https://gitlab.ba.rivosinc.com/api/v4/projects/38/packages/generic/firmwares/1/fw_dynamic.elf".format(os.environ["CI_JOB_TOKEN"]).split(" "))
    print("OK")

def userspace_prepare_vm(c, kernel_version):
    # Prepare the image
    c.put("prepare_vm_from_guest.sh")
    c.run("bash prepare_vm_from_guest.sh")

def userspace_launch_tests(c, kernel_version, long_valid, subset):
    list_tests = glob.glob("tests/{}/*".format(subset))
    for test in list_tests:
        test_name = os.path.basename(test)
        print("*** {}...".format(test_name))

        filename = os.path.join(test, "main.py")
        with open(filename, "rb") as py:
            test_code = py.read()

        exec(test_code, globals(), locals())

def userspace_validate_kernel(c, kernel_version):
    print("* Validating {}...".format(kernel_version), end = "")

    # Mount the shared directory that contains the linux sources
    c.sudo("mkdir -p /opt/sources/linux/")
    c.sudo("mount -t 9p -o trans=virtio host0 /opt/sources/linux/ -oversion=9p2000.L")

    userspace_launch_tests(c, kernel_version, args.long_valid, "all")

def userspace_validate_kasan_kernel(c, kernel_version):
    # Kasan specific validation
    userspace_launch_tests(c, kernel_version, args.long_valid, "kasan")

    # Default validation
    userspace_validate_kernel(c, kernel_version)

def userspace_install_kernel(c, version):
    print("* Installing kernel {}...".format(version), end = "")

    # Install the kernel to test.
    # FIXME even if only one deb is published, looping here is dirty.
    for f in Path("/rivos/sysroot/riscv/boot/{}".format(version)).glob("*.deb"):
        basename = os.path.basename(f)
        c.put(f)
        c.sudo("sudo dpkg -i {}".format(basename))
        print("OK")
        return

    print("FAIL")
    raise RuntimeError("FAIL: no deb found for kernel {}".format(version))

def launch_vm_and_execute_userspace_fn(fn, kernel_version, satp_mode = "sv48"):
    print("* Launching the VM in {}...".format(satp_mode), end = "")

    with open("vm_output", "a") as f:
        complete_qemu_cmd = qemu_cmd.format(satp_mode, vm_path, os.path.join(os.getcwd(), "../.."))
        print(complete_qemu_cmd)
        with subprocess.Popen(complete_qemu_cmd.split(" "), text = True, stdout = f, stderr = subprocess.STDOUT) as vm_proc:
            print("OK")

            print("* Connecting via ssh...", end = "")
            sys.stdout.flush()

            with Connection(host_vm, connect_kwargs = { "password": host_pwd, "timeout": 180, "banner_timeout": 100, "auth_timeout": 180 }) as c:
                for i in range(0, SSH_MAX_TRIALS):
                    print(".", end = "")
                    sys.stdout.flush()

                    try:
                        c.open()
                    except:
                        pass
                    if c.is_connected:
                        print("OK")

                        try:
                            fn(c, kernel_version)
                        except:
                            # TODO Should not poweroff at first exception, but
                            # rather file that somewhere.
                            print("* Powering off the VM...")
                            c.sudo("poweroff")
                            # FIXME wait for the last kernel message "reboot: Power down"
                            # Give the VM the time to stop properly and terminate the process
                            time.sleep(30)
                            vm_proc.terminate()
                            vm_proc.wait()
                            raise

                        print("* Powering off the VM...")
                        c.sudo("poweroff")
                        # FIXME wait for the last kernel message "reboot: Power down"
                        # Give the VM the time to stop properly and terminate the process
                        time.sleep(30)
                        vm_proc.terminate()
                        vm_proc.wait()

                        return

                    time.sleep(SSH_SLEEP_INTERVAL_SEC)

                if i == SSH_MAX_TRIALS - 1:
                    print("FAIL")
                    vm_proc.terminate()
                    vm_proc.wait()
                    raise TimeoutError

if __name__ == "__main__":
    args = parse_args()

    host_dl_firmware()

    # Prepare or simply download a prepared VM
    if args.dl_prepared_vm:
        host_dl_prepared_vm()
    elif args.use_local_vm:
        print("### Using local VM ###")
    else:
        host_prepare_vm()
        launch_vm_and_execute_userspace_fn(userspace_prepare_vm, "")

        if args.only_prepare_vm:
            host_finish_prepare_vm()
            sys.exit(0)

    validate_fn = {
            "ubuntu_defconfig": userspace_validate_kernel,
            "ubuntu_kasan_inline_defconfig": userspace_validate_kasan_kernel,
            "ubuntu_kasan_outline_defconfig": userspace_validate_kasan_kernel,
    }

    for version in args.versions.split(","):
        print("### Testing {} ###".format(version))
        try:
            if not args.no_kernel_install:
                launch_vm_and_execute_userspace_fn(userspace_install_kernel, version)

            if args.satp_valid:
                for satp_mode in satp_mode_list:
                    launch_vm_and_execute_userspace_fn(validate_fn[version], version, satp_mode)
            else:
                launch_vm_and_execute_userspace_fn(validate_fn[version], version)

        except TimeoutError:
            print("### ERROR: Timeout {} ###".format(version))
            sys.exit(-1)
        except Exception as e:
            print("### ERROR: Fail {} ###".format(version))
            print(e)
            sys.exit(-1)
