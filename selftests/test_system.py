import pytest

import optest

from optest.system import BaseSystem
from optest.console import FileConsole


class StubSystem(BaseSystem):
    def __init__(self, input_file):
        self.input_file = input_file
        self.host_on = False
        self.bmc_on = False

        con = FileConsole(self.input_file)

        super().__init__(console=con)

    # host stubs
    # FIXME: should con remain active even across host reboots? if the BMC dies it can go away
    # so maybe that's somethignwe just have to deal with
    def host_power_on(self):
        self.host_on = True
    def host_power_off(self):
        self.host_on = False
    def host_power_off_hard(self):
        self.host_power_off()
    def host_power_is_on(self): # -> Bool
        return self.host_on

@pytest.fixture
def off_system():
    sys = StubSystem("test_data/bootlogs/boot-to-os")
    sys.host_power_off()
    sys.get_console().connect()

    yield sys
#    sys.prepare()

def test_boot_os(off_system):
    sys = off_system

    # FIXME: how is the "off" state handled?
    sys.host_power_on()
    sys.waitfor('ipling')
    sys.waitfor('petitboot')
    sys.waitfor('login')

def test_boot_pb(off_system):
    sys = off_system

    # FIXME: how is the "off" state handled?
    sys.host_power_on()
    sys.waitfor('ipling')
    sys.waitfor('skiboot')
    sys.waitfor('login')

    # powering off sort of breaks our model, but it's a special case anyway

    # FIXME: what do we have to verify where we are?
