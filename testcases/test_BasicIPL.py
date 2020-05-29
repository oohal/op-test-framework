#!/usr/bin/env python3
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2015,2017
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#

'''
Basic IPL and reboot tests
--------------------------

These can be used as tests themselves to check all IPL and reboot types, or
can be invoked on the command line to boot the machine a certain way or into
a specific state.
'''

import logging
import pexpect

import pytest
import optest

#from optest.OpTestSystem import OpSystemState
#from optest.OpTestError import OpTestError

log = logging.getLogger(__name__)

from optest.petitboot import PetitbootHelper

# hmm, any way we get get this
@pytest.fixture()
def optest_system_off(optest_system):
    optest_system.get_console().connect()
    optest_system.poweroff()
    yield optest_system

class TestBasicIPL():
    def test_boot_to_petitboot(self, optest_system_off):
        '''
        Boot to the Petitboot menu. It does *not* cancel any automatic boot
        countdown sequence.

        It will force the machine off first, so it *will* do an IPL.
        '''

        sys = optest_system_off

        assert sys.host_power_is_on() == False

        log.debug("IPL: starting BootToPetitboot test")

        sys.boot_to('petitboot')

        pb = PetitbootHelper(sys.get_console())
        pb.goto_shell()

        uname, rc = sys.run_command("uname -r")
        assert "openpower" in uname[0]
        assert rc == 0

        log.debug("IPL: BootToPetitboot test passed")

#    def test_GotoPetitbootShell(cv_SYSTEM):
#        """
#        We goto petitboot shell rather than do the off/on-to-petitboot
#        shell so that the skiroot test suite time to run each test is
#        a bit more accurate, rather than hiding the first IPL in the
#        first test that's run.
#        """
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#
#    def test_offonoff(cv_SYSTEM):
#        """ Off -> On -> Off """
#        sys.host_power_off() # wait state?
#        sys.host_power_on()
#        sys.waitfor('petitboot')
#        sys.host_power_on()
#
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#
#    def test_rightoff(cv_SYSTEM):
#        """
#        ??? -> Off
#        """
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#
#    def test_SoftPowerOff(cv_SYSTEM):
#        '''
#        Do a soft power off (i.e. polite, asking the OS to shut down).
#        '''
#        log.debug("IPL: starting SoftPowerOff test")
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        cv_SYSTEM.sys_power_soft()
#        log.debug("IPL: soft powered off")
#        cv_SYSTEM.set_state(OpSystemState.POWERING_OFF)
#        log.debug("set state, going to off")
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        log.debug("IPL: SoftPowerOff test completed")
#
#    def test_BootToOS(cv_SYSTEM):
#        '''
#        Boot the default Operating System on the Host.
#
#        This will force and IPL and then look to get to a login prompt.
#        '''
#        log.debug("IPL: starting BootToOS test")
#        log.debug("IPL: Currently powered off!")
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        cv_SYSTEM.goto_state(OpSystemState.OS)
#        log.debug("IPL: BootToOS test completed")
#        # We booted, SHIP IT!
#
#    def test_HardPowerCycle(cv_SYSTEM):
#        '''
#        Get to Petitboot, then issue a hard power cycle from the BMC,
#        checking that we can get back to Petitboot.
#        '''
#        log.debug("IPL: starting HardPowerCycle test")
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        cv_SYSTEM.sys_power_reset()
#        cv_SYSTEM.set_state(OpSystemState.IPLing)
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        log.debug("IPL: HardPowerCycle test completed")
#
#
#    def test_PowerOff(cv_SYSTEM):
#        '''
#        Get to Petitboot, then ask the BMC for a normal power off sequence,
#        checking that the host did indeed power off.
#        '''
#        log.debug("IPL: starting PowerOff test")
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        cv_SYSTEM.sys_power_off()
#        cv_SYSTEM.set_state(OpSystemState.POWERING_OFF)
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        log.debug("IPL: PowerOff test completed")
#
#"""
#    def test_BMCReset(cv_BMC, cv_SYSTEM):
#        '''
#        Reboot the BMC with the host off. This will check that the host is also
#        powered off when the BMC comes back.
#        '''
#        log.debug("IPL: starting BMCReset test")
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        cv_BMC.reboot()
#
#        c = 0
#        while True:
#            try:
#                cv_SYSTEM.sys_wait_for_standby_state()
#            except OpTestError as e:
#                c += 1
#                if c == 10:
#                    raise e
#            else:
#                break
#
#        cv_SYSTEM.set_state(OpSystemState.POWERING_OFF)
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        log.debug("IPL: BMCReset test completed")
#
#    def test_BMCResetThenRebootHost(cv_BMC, cv_SYSTEM):
#        '''
#        Reboot the BMC with the host on and once the BMC is back, reboot
#        the host.
#        '''
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#        cv_BMC.reboot()
#        console = cv_SYSTEM.console
#        console.run_command_ignore_fail("dmesg -r|grep '<[4321]>'")
#        console.run_command_ignore_fail(
#            "grep ',[0-4]\\]' /sys/firmware/opal/msglog")
#        console.pty.sendline("reboot")
#        cv_SYSTEM.set_state(OpSystemState.IPLing)
#        try:
#            cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#        except pexpect.EOF:
#            cv_SYSTEM.goto_state(OpSystemState.OFF)
#            cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#
#    def test_OutOfBandWarmReset(cv_SYSTEM):
#        '''
#        Does an IPL to petitboot, and then do a 'warm reset', checking that
#        we can boot back up to Petitboot.
#        '''
#        log.debug("IPL: starting OutOfBandWarmReset test")
#        # FIXME currently we have to go via OFF to ensure we go to petitboot
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        cv_SYSTEM.sys_warm_reset()
#        cv_SYSTEM.goto_state(OpSystemState.OFF)
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT)
#        cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
#        log.debug("IPL: OutOfBandWarmReset test completed")
#"""
#
