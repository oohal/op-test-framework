#!/usr/bin/env python3
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/common/OpTestSystem.py $
#
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
# IBM_PROLOG_END_TAG

# @package OpTestSystem
#  System package for OpenPower testing.
#
#  This class encapsulates all interfaces and classes required to do end to end
#  automated flashing and testing of OpenPower systems.

import time
import pexpect

from . import logger
from .exceptions import *
log = logger.optest_logger_glob.get_logger(__name__)

class SysState():
    '''
    Defines one of the states a system can be in.

    We make a few assumptions about system states can work, namely:

    1. There's a linear flow of states. We always go through the previous
       states before entering the next one. This is a bit awkward for things
       like mpipl where there are unusual state transitions. However, it
       simplifies the general case so punting that work to the test case is
       probably a reasonable trade off.

    2. After powering on the host the system will boot automatically. The state
       machinery here just observes the boot process rather than driving it.

       The exception to the above is states which define an .action() function.
       That is used for things like the OS login prompt where some action is
       needed to continue the boot process.

        FIXME: hmm, we might be able to wrap that up in wait_entry(), maybe not since
               we want to support waitat()
    '''
    def __init__(self, name, entry_timeout, exit_timeout):
        self.name = name
        self.exit_timeout = exit_timeout
        self.entry_timeout = entry_timeout

    def __str__(self):
        return self.name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if isinstance(other, SysState):
            return self.name == other.name
        return False

    def run(self, stop):
        raise NotImplementedError()

    def resume(self, stop):
        ''' resumes the boot starting from where it was stopped '''
        raise NotImplementedError()

# helper functions for the ConsoleState pattern tables
def error_pattern(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))

def missed_state(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))

class ConsoleState(SysState):
    '''
    Many system states we can detect by just watching the system console. This
    helper implements a pile of expect logic to detect when we've entered into
    and exited a given state.
    '''
    def __init__(self, name,
                 entry_patterns, entry_timeout, exit_patterns, exit_timeout):
        self.entry_patterns = entry_patterns
        self.exit_patterns = exit_patterns
        super().__init__(name, entry_timeout, exit_timeout)

    def _watch_for(self, system, patterns, timeout):
        expect_table = list(patterns.keys())

        # FIXME: where's the right place to implement the console reconnect? possibly here...
        r = system.console.expect(expect_table, timeout=timeout)
        cb = patterns[expect_table[r]]
        if cb:
            raise Exception("hit error pattern") # FIXME: maybe we should... call the callback?
        return expect_table[r]

    def run(self, system, exit_at):
        self._watch_for(system, self.entry_patterns, self.entry_timeout)
        if exit_at:
            return False

        self._watch_for(system, self.exit_patterns, self.exit_timeout)
        return True

class BaseSystem(object):
    def __init__(self, conf=None, host=None, console=None, pdu=None):
        self.host = host
        self.console = console
        self.pdu = pdu

        # XXX: should setting this up be the job of the subclass? probably
        self.state_table = []
        self.last_state = None

        if conf and conf.get('power_off_delay'):
            self.power_off_delay = conf.get['power_off_delay']
        else:
            self.power_off_delay = 120

        log.debug("Initialised {}".format(self.__class__.__name__))

    ############################################################################
    # Power Control
    #
    # These are relatively low level functions that are intended for internal use
    # they just "do the thing" without any of the state machiney song and dance.
    #
    # classes inheriting OpTestSystem should implement these
    ############################################################################

    def host_power_on(self):
        raise NotImplementedError() # Turn the host power on
    def host_power_off(self):
        raise NotImplementedError() # Ask the OS to do a graceful shutdown
    def host_power_off_hard(self):
        raise NotImplementedError() # Remove host power

    def host_power_is_on(self): # -> Bool
        raise NotImplementedError()

    # we use this to check if the BMC is still usable or not
    # This should allow us to catch NC-SI induced headaches, etc
    # XXX: should we distingush between "alive" and "ready"? with openbmc we
    # can be responding to ping, but not ready to boot. Same with the FSP.
    def bmc_is_alive(self):
        raise NotImplementedError()

    # Assuming we have one...
    def pdu_power_on(self):
        raise NotImplementedError()
    def pdu_power_off(self):
        raise NotImplementedError()

    def collect_debug(self):
        raise NotImplementedError()

    def boot(self):
        # goto_state does a power off for us. Run until booted.
        self.boot_to(self.state_table[-1].name)

    def poweroff(self, softoff=True):
        ''' helper for powering off the host and reset our state tracking '''

        self.last_state = None

        # possibly excessive, but we've found some systems where it can take
        # a while for the BMC to work again due to NC-SI issues.
        if softoff:
            self.host_power_off()

            for i in range(self.power_off_delay):
                # the BMC can flake out while rebooting the host which causes
                # us to lose the console, etc.
                # the polling here will cause errors. Catch any exceptions that
                # crop up until we've hit the timeout.
                if self.bmc_is_alive() and not self.host_power_is_on():
                    return

                try:
                    if not self.host_power_is_on():
                        return

                    # run expect with no patterns so we get output during poweroff
                    # and so we catch any crashes that might happen while powering
                    # off
                    self.expect([pexpect.TIMEOUT], timeout=1)
                    log.info("Waiting for power off {}/{}s".format(i, self.power_off_delay))
                    print("Waiting for power off {}/{}s".format(i, self.power_off_delay))

                except Exception as e:
                    raise e

            log.info("Timeout while powering off host. Yanking power now")

        # try a little harder...
        self.host_power_off_hard()
        for i in range(self.power_off_delay):
            if not self.host_power_is_on():
                return

            self.expect(timeout=1)

        # FIXME: use a precise exception type
        raise Exception("host hasn't turned off after yanking power")


    ############################################################################
    # Console Wrangling
    #
    # Returns the OpTestConsole for the host
    #
    ############################################################################

    # return the host console object
    def get_console(self):
        ''' returns the system's host console.

        NB: This always works, even if the host is off. Actual interactions
        throught the console require the host to be powered on though. Might
        seem obvious, but I'm putting it in writing so the expectation for
        simulated systems is clear. In the case of Qemu at least there's no
        underlying pty object unless qemu is actually running.
        '''

        return self.console

    def run_command(self, cmd, timeout=60):
        return self.console.run_command(cmd, timeout)

    def expect(self, params, timeout):
        return self.console.expect(params, timeout)

    ############################################################################
    #
    # System state tracking circus.
    #
    ############################################################################

    def _add_state_list(self, new_states):
        self.state_table.extend(new_states)

    def _add_state(self, new_state):
        self.state_table.append(new_state)

    def _get_state(self, name):
        for s in self.state_table:
            if s.name == name:
                return s

        msg = "{} is not supported by this system type".format(target)
        raise UnsupportedStateError(msg)

    def assume_state(self, new_state_name):
        ''' Updates the state tracking machinery to reflect reality

        NB: You probably should use goto_state() rather than this. However,
            if you're doing something to change the underlying system state,
            such as forcing a reboot, then use this to sync the state
            tracking up with reality.
        '''
        self.last_state = self._get_state(new_state_name)

    def boot_to(self, target_name):
        target = self._get_state(target_name)

        log.debug('booting to state {}'.format(target))
        self.poweroff()
        self.host_power_on()

        for s in self.state_table:
            self.assume_state(s.name)

            log.info('state {} - running'.format(s))

            if s == target:
                s.run(self, True);
                log.info("state {} - stopping, target reached".format(target))
                return

            s.run(self, False);
            log.info('state {} - done'.format(s.name))
