import pytest
import optest

from optest import system
from optest.openpower import OpSystem
from optest.console import FileConsole

class StubHost():
    def username(self):
        pass

class StubSystem(OpSystem):
    def __init__(self, input_file):
        self.input_file = input_file
        self.host_on = False
        self.bmc_on = False

        con = FileConsole(self.input_file)

        super().__init__(console=con, host=StubHost())

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
    def bmc_is_alive(self):
        return True

@pytest.fixture(params=["p8-boot-to-pb.log", "p9-boot-to-pb.log"])
def off_system(request):
    sys = StubSystem("test_data/bootlogs/{}".format(request.param))
    sys.host_power_off()
    sys.get_console().connect()

    yield sys

def test_boot_pb(off_system):
    sys = off_system

    sys.host_power_on()
    # FIXME: resume boot support
#    sys.boot_to('hostboot')
#    sys.boot_to('skiboot')

    # raises since boot_to will try and park at the petitboot menu so its
    # console interactions don't do anything. That's fine for this test.
    with pytest.raises(optest.ConsoleSettings):
        sys.boot_to('petitboot')
