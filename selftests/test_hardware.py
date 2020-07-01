import pytest

import optest
from optest import system
from optest.system import BaseSystem
from optest.console import FileConsole
from optest.petitboot import PetitbootHelper

import misc

@pytest.fixture(params=["qemu", "smc", "fsp"])
def system(request):
    config = misc.get_config(request.param)
    sys = config.create_system()

    # FIXME: test prep step?
    sys.get_console().connect()

    yield sys

    sys.poweroff()
    config.cleanup()

def test_os_boot(system):
    if not system.has_state('os'):
        raise pytest.skip("System doesn't support the os state")

    if not system.host.username():
        raise pytest.skip("No os login details")

    c = system.get_console()

    system.poweroff()
    system.boot_to('os')

    os_uname = c.run_command('uname -a')

    assert "openpower" not in os_uname

def test_off_on_off_on(system):
    c = system.get_console()

    system.poweroff()
    system.boot_to('petitboot')
    PetitbootHelper(c).goto_shell()
    out1 = c.run_command('uname -a')

    system.poweroff()
    system.boot_to('petitboot')
    PetitbootHelper(c).goto_shell()
    out2 = c.run_command('uname -a')

    assert out1 == out2

def test_bmc_is_alive(system):
    assert system.bmc_is_alive() == True
