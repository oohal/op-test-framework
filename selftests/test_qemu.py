import pytest
import optest

from optest.qemu import QemuSystem
from optest.petitboot import PetitbootHelper

import misc

@pytest.fixture
def qemu():
    config = misc.get_config('qemu')

    qemu = config.create_system()
    qemu.get_console().connect()

    yield qemu

    qemu.host_power_off()
    config.cleanup()

def test_qemu_boot_nokernel(qemu):

    # HACK: zap the kernel (and pnor) so we crash at boot
    qemu.kernel = None
    qemu.pnor = None

    qemu.host_power_on()

    with pytest.raises(optest.SkibootAssert):
        qemu.waitfor('petitboot') # should fail since there's no kernel image
    qemu.host_power_off()

def test_qemu_boot_pb(qemu):
    qemu.host_power_on()
    qemu.waitfor('skiboot')
    qemu.waitfor('petitboot') # should fail with a timeout

    pb = PetitbootHelper(qemu.get_console())
    pb.goto_shell()

    qemu.run_command("echo hi")


def test_qemu_goto_state(qemu):
    qemu.goto_state('petitboot')
    pb = PetitbootHelper(qemu.get_console())
    pb.goto_shell()
