import pytest
import optest

from optest.qemu import QemuSystem
from optest.petitboot import PetitbootHelper

@pytest.fixture
def qemu_binary():
    yield "/home/oliver/code/qemu/ppc64-softmmu/qemu-system-ppc64"

@pytest.fixture
def skiboot_lid():
    yield "test_data/skiboot.lid.nophbs"

@pytest.fixture
def qemu(qemu_binary, skiboot_lid):
    # FIXME: parameterise these
    kernel      = "test_data/vmlinux"
    initramfs   = "test_data/petitfs"
    sys = QemuSystem(kernel=kernel,
                     initramfs=initramfs,
                     qemu_binary=qemu_binary,
                     skiboot=skiboot_lid)

    sys.host_power_off()
    sys.host_power_on()
    sys.get_console().connect()

    yield sys

    sys.host_power_off()

def test_qemu_boot_nokernel(qemu_binary, skiboot_lid):
    sys = QemuSystem(qemu_binary=qemu_binary, skiboot=skiboot_lid)
    sys.host_power_off()
    sys.host_power_on()
    sys.get_console().connect()

    with pytest.raises(optest.SkibootAssert):
        sys.waitfor('petitboot') # should fail since there's no kernel image
    sys.host_power_off()

def test_qemu_boot_pb(qemu):
    qemu.waitfor('skiboot')
    qemu.waitfor('petitboot') # should fail with a timeout

    pb = PetitbootHelper(qemu.get_console())
    pb.goto_shell()

    qemu.run_command("echo hi")


def test_qemu_goto_state(qemu):
    qemu.goto_state('petitboot')
    pb = PetitbootHelper(qemu.get_console())
    pb.goto_shell()
