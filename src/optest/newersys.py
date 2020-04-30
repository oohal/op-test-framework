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
import subprocess
import pexpect
import socket
import errno
import inspect

from . import OpTestIPMI  # circular dependencies, use package
from .OpTestConstants import OpTestConstants as BMC_CONST
from .OpTestError import OpTestError
from .OpTestUtil import OpTestUtil
from .Exceptions import HostbootShutdown, WaitForIt, RecoverFailed, UnknownStateTransition
from .Exceptions import ConsoleSettings, UnexpectedCase, StoppingSystem, HTTPCheck
from .OpTestSSH import OpTestSSH

import logging
from . import OpTestLogger
log = OpTestLogger.optest_logger_glob.get_logger(__name__)


class ErrorPattern(Exception):
    pass
class MissedState(Exception):
    pass

# called when we get to the login prompt when we wanted petitboot (i.e. missed PB)
def error_pattern(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))

def missed_state(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))


ipling_expect_table = {
    'istep 4.' : None,
    'Welcome to Hostboot' : None,
}

skiboot_expect_table = {
    'OPAL v6.' : None,
    'OPAL v5.' : None,
    'SkiBoot' : None,
}

# each expect table indicates when we've *entered* that state
pb_expect_table = {
    'Petitboot': None,
    'x=exit': None,
    '/ #': None,
    'shutdown requested': error_pattern, # FIXME: too broad, see GH issue
    'login: ': missed_state,
#    'mon> ': self.xmon_callback,
#    'dracut:/#': self.dracut_callback,
#    'System shutting down with error status': self.guard_callback,
    'Aborting!': self.error_pattern,
}

login_expect_table = {
    'login: ': None,
    '/ #': self.error_pattern,
    'mon> ': self.error_pattern,
#    'dracut:/#': self.dracut_callback,
}

class SysState():
    '''
    defines one of the states a system can be in. Note that the OpTestSystem
    requires a linear flow of states and you can only reach one system state
    by going through all the previous ones.

    Making this assumption allows us to simplify the internal state machine
    considerably since we don't need to deal with arbitrary movements
    between states. If a prior state is requested we can handle it by
    powering the system off and re-IPLing.
    '''
    def __init__(self, name, patterns, timeout, stop_fn):
        self.name = name
        self.patterns = patterns # patterns we're looking for to indicate this state was reached
        self.timeout = timeout   # how long this state is expected to last
        self.stop_fn = stop_fn   # function to call to stop the IPL in this state

    def __hash__(self)
        return self.name.__hash__()

    def __eq__(self, other):
        return self.name == other.name

# ordered list of possible states for this system
state_table = [
        SysState('off',         True,   None,           1),
        SysState('ipling',      False,  ipling_expect_table,    120),
#        SysState('skiboot',     False,  ski_patterns    60),
        SysState('petitboot',   True,   pb_expect_table, 60),
        SysState('login',       True,   login_expect_table, 180), # network cards suck
#        SysState('os',          True,   os_patterns,    30),
]

class OpTestSystem(object):
    def __init__(self,
                 host=None,
                 console=None,
                 pdu=None)

        self.host = host
        self.console = console

        # XXX: should setting this up be the job of the subclass? probably
        self.state_table = []
        self.state_dict = {}
        self.state_idx = {}

        # FIXME: move this to subclasses
        for s in state_table:
            self._add_state(s)

        # a list of error patterns to look for while expect()ing the
        # host console FIXME: these are in OpExpect currently, which is
        # dumb
        self.error_patterns = []

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
    def bmc_is_alive(self):
        raise NotImplementedError()

    # Assuming we have one...
    def pdu_power_on(self):
        raise NotImplementedError()
    def pdu_power_off(self):
        raise NotImplementedError()

    def collect_debug(self):
        raise NotImplementedError()

    def poweroff(self, soft_first=True):
        ''' helper for powering off the host and reset our state tracking '''
        self.reset_states()

        self.host_power_off()
        if soft_first:
            for i in range(self.power_off_delay):
                if not self.host_power_is_on():
                    return
                time.sleep(1)
            log.info("Timeout while powering off host. Yanking power now")

        # try a little harder...
        self.host_power_off_hard():
        for i in range(self.power_yank_delay):
            if not self.host_power_is_on():
                return
        raise "host hasn't turned off after yanking power"


    ############################################################################
    # Console Wrangling
    #
    # Returns the OpTestConsole for the host
    #
    ############################################################################

    # return the underlying console object, useful for wrangling expect
    def get_console(self):
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

    def _add_state(self, new_state):
        self.state_table.append(new_state)
        self.state_dict[new_state] = new_state
        self.state_idx[new_state] = len(self.state_table) - 1

    def set_state(self, new_state):
        ''' Updates the state tracking machinery to reflect reality

        NB: You probably should use goto_state() rather than this. However,
            if you're doing something to change the underlying system state,
            such as forcing a reboot, then use this to sync the state
            tracking up with reality.
        '''

        # TODO: update error patterns?
        for i in range(self.state_idx[state]):
            self.visited[i] = True
        self.last_state = new_state

    def waitfor(self, state):
        ''' waits for the system to reach the requested state

        It's up to the caller to initiate the state transition.
        e.g.
            To get to petitboot you would need to do:
            system.power_off()
            system.waitfor('off')
            system.power_on()
            system.waitat('petitboot')

        This is a little verbose, but moving to a specific state generally
        isn't required
        '''

        if not self.states.get(s, None):
            raise ValueError("System doesn't support this state?")
        if self.visited[state]:
            raise ValueError('State already visited. Poweroff required')

        expect_table = s.patterns.keys()

        # raises an exception on timeout, EOF, or any of our error patterns
        r = self.console.expect(expect_table, timeout=s.timeout)

        # error pattern?
        cb = s.patterns(expect_table[r])
        if cb:
            raise "hit error pattern" # FIXME: halfassed

        self.set_state(s)


    def waitat(self, target):
        if not self.state_dict[target].interrupt:
            raise ValueError("state can't be waited at")

        self.waitfor(target)
        self.state_dict[target].interrupt()
