
import optest
import optest.newsys

from optest.newsys import OpTestSystem
from optest.OpTestConsole import FileConsole

class StubSystem(OpTestSystem):
    def __init__(self, input_file):
        self.input_file = input_file
        self.host_on = False
        self.bmc_on = False

        con = FileConsole(self.input_file)

        super().__init__(console=con, trydetect=True)

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

    # bmc stubs
    def bmc_is_alive(self):
        return self.bmc_on
    def bmc_power_off(self):
        self.host_power_off()
        self.bmc_on = False
    def bmc_power_on(self):
        self.bmc_on = True

def test_goto_petitboot():
    sys = StubSystem("test_data/bootlogs/boot-to-pb")
    sys.goto_state(optest.newsys.OpSystemState.PETITBOOT)
    assert sys.state == optest.newsys.OpSystemState.PETITBOOT

def test_goto_os():
    sys = StubSystem("test_data/bootlogs/boot-to-os")
    sys.goto_state(optest.newsys.OpSystemState.OS)
    assert sys.state == optest.newsys.OpSystemState.OS


# XXX: Should this fail? When we get to the point where we've got to petitboot
# in the console log there's more output available. This is similar to what
# might happen if we had network problems between the op-test system and the
# system under test.
#
# I'll have to think about it. Maybe we should verify that we're in the state
# we think we're in?
def test_goto_pb_with_os_data():
    sys = StubSystem("test_data/bootlogs/boot-to-os")
    sys.goto_state(optest.newsys.OpSystemState.PETITBOOT)
    assert sys.state == optest.newsys.OpSystemState.PETITBOOT
