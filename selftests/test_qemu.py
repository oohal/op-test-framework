import pytest
import optest

from optest.qemu import QemuSystem

@pytest.fixture
def qemu():
    # FIXME: parameterise these
    qemu_binary = "/home/oliver/code/qemu/ppc64-softmmu/qemu-system-ppc64"
    qemu_binary = "qemu-system-ppc64"
    kernel      = "/home/oliver/code/op-test/selftests/test_data/vmlinux"
    initramfs   = "/home/oliver/code/op-test/selftests/test_data/petitfs"
    skiboot     = "test_data/skiboot.lid.nophbs"
    sys = QemuSystem(kernel=kernel, initramfs=initramfs, qemu_binary=qemu_binary, skiboot=skiboot)
    sys.host_power_off()
    sys.host_power_on()
    sys.get_console().connect()

    yield sys

    sys.host_power_off()

def test_qemu_boot_nokernel():
    sys = QemuSystem(
            qemu_binary="/home/oliver/code/qemu-op/ppc64-softmmu/qemu-system-ppc64"
        )
    sys.host_power_off()
    sys.host_power_on()
    sys.get_console().connect()

    sys.waitfor('skiboot')
    with pytest.raises(optest.SkibootAssert):
        sys.waitfor('petitboot') # should fail since there's no kernel image
    sys.host_power_off()

def test_qemu_boot_pb(qemu):
    qemu.waitfor('skiboot')
    qemu.waitfor('petitboot') # should fail with a timeout
