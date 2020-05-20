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
log = logger.optest_logger_glob.get_logger(__name__)

class UnsupportedStateError(Exception):
    pass
class ErrorPattern(Exception):
    pass
class MissedState(Exception):
    pass

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
    def __init__(self, name):
        self.name = name
        # patterns we're looking on the console indicate this state was
        # reached.
        #
        # FIXME: Doesn't work terribly well for FSP systems
#        self.patterns = entry_patterns
#        self.pause  = pause  # function to call to pause the IPL at this state
#        self.resume = resume # function to call continue the IPL from this state
#        self.verify = verify # function to call to check that we're in this state

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if isinstance(other, SysState):
            return self.name == other.name
        return False

    # FIXME: Wonder if we should even bother with entry / exit stuff and
    # just have the one state handling function.
    #
    # FIXME: It's not clear to be how the state system should interact with cons
    # reconnect stuff. If the console dropped we can miss the state transitions
    # we're looking for. Old op-test handled this by "kicking" the console
    # on reconnect, so if we were in a wait state (petitboot menu, os login)
    # we could keep going. Even with that it's still possibly to miss
    # a transition since the default petitboot timeout isn't that long (10s)
    # and ipmitool won't notice the SOL flaking out instantly.
    def wait_entry(self, system):
        '''
        Polls the system to check if we're entered this state.

        Returns when the system is in this state.
        Raises BootError we time out waiting for the state, or some other error
        occurs.
        '''
        raise NotImplementedError()

    def wait_exit(self):
        '''
        Returns when we detect the system has left this state.

        Raises BootError if we time out waiting or some other error occurs
        '''
        raise NotImplementedError()

class ConsoleState(SysState):
    '''
    Many system states we can detect by just watching the system console. This
    helper implements a pile of expect logic to detect when we've entered into
    and exited a given state.
    '''
    def __init__(self, name,
                 entry_patterns, entry_timeout, exit_patterns, exit_timeout):
        self.entry_timeout = entry_timeout
        self.entry_patterns = entry_patterns

        self.exit_timeout = exit_timeout
        self.exit_patterns = exit_patterns

        super().__init__(name)

    def _watch_for(self, system, patterns, timeout):
        expect_table = list(patterns.keys())

        r = system.console.expect(expect_table, timeout=timeout)
        cb = patterns[expect_table[r]]
        if cb:
            raise Exception("hit error pattern") # FIXME: maybe we should... call the callback?

    def wait_entry(self, system, waitat=False):
        self._watch_for(system, self.entry_patterns, self.entry_timeout)

#        if self.action:
#            self.action(system)
        if waitat:
            raise "implement me"

    def wait_exit(self, system):
        self._watch_for(system, self.exit_patterns, self.exit_timeout)


class BaseSystem(object):
    def __init__(self, host=None, console=None, pdu=None):
        self.host = host
        self.console = console
        self.pdu = pdu

        # XXX: should setting this up be the job of the subclass? probably
        self.state_table = []
        self.states = {}
        self.state_idx = {}
        self.visited = {}

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

    def poweron(self):
        self.reset_states()
        self.host_power_on()

    def poweroff(self, softoff=True):
        ''' helper for powering off the host and reset our state tracking '''
        #self.reset_states()

        # possibly excessive, but we've found some systems where it can take
        # a while for the BMC to work again due to NC-SI issues.
        self.power_off_delay = 120
        if softoff:
            self.host_power_off()

            for i in range(self.power_off_delay):
                if not self.host_power_is_on():
                    return

                # run expect with no patterns so we get output during poweroff
                # and so we catch any crashes that might happen while powering
                # off
                self.expect([pexpect.TIMEOUT], timeout=1)
            log.info("Timeout while powering off host. Yanking power now")

        # try a little harder...
        self.host_power_off_hard()
        for i in range(self.power_yank_delay):
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

    def _add_state(self, new_state):
        self.state_table.append(new_state)
        self.states[new_state.name] = new_state
        self.state_idx[new_state] = len(self.state_table) - 1
        self.visited[new_state] = False

    def set_state(self, new_state):
        ''' Updates the state tracking machinery to reflect reality

        NB: You probably should use goto_state() rather than this. However,
            if you're doing something to change the underlying system state,
            such as forcing a reboot, then use this to sync the state
            tracking up with reality.
        '''

        # TODO: update error patterns?
        for i in range(self.state_idx[new_state]):
            self.visited[self.state_table[i]] = True
        self.last_state = new_state # XXX: Needed?

    def waitfor(self, target_state):
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

        s = self.states.get(target_state, None)
        if not s:
            raise ValueError("System doesn't support {}".format(target_state))
        if self.visited[s]:
            raise ValueError('State already visited. Poweroff required')

        log.info('waiting to enter {}'.format(s.name))
        s.wait_entry(self, False)
        self.set_state(s)
        log.info("Reached {}".format(target_state))

    def waitat(self, target):
        if not self.states[target].interrupt:
            raise ValueError("state can't be waited at")

        self.waitfor(target)
        self.states[target].stop()

    def goto_off(self):
        '''
        Going to the off state is the only allowed "backwards" state transition
        so it gets some special treatment. The main problem is that we can't
        keep track of what state the system is in since the current test is
        free to change it under our feet.

        is in we don't know what's the "correct" way to power off the system
        or how we're supposed to know the system is actually off.

        For all the other boot states we can usually just sit and wait

        There are some system specific sideband measures that we can use to
        work this out though. For example, openbmc has the `obmcutil power`
        command which tells you the state of the
        '''

    def goto_state(self, target):
        s = self.states[target]
        supported_states = [s.name for s in self.state_table]
        if target not in supported_states:
            msg = "{} is not supported by this system type".format(target)
            raise UnsupportedStateError(msg)

        log.debug('goto_state target {}'.format(target))
        self.poweroff()
        self.host_power_on()

        for s in self.state_table:
            log.info('waiting to enter {}'.format(s.name))
            s.wait_entry(self, False)
            self.set_state(s)

            # landed at our target state...
            if s.name == target:
                log.info("Reached target state of {}".format(target))
                return

            log.debug('waiting to exit {}'.format(s.name))
            s.wait_exit(self)
            log.debug('waiting to exit {}'.format(s.name))

# called when we get to the login prompt when we wanted petitboot (i.e. missed PB)
def error_pattern(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))

def missed_state(pattern, context):
    raise ErrorPattern("pattern: {}, context: {}".format(pattern, value))

# each expect table indicates when we've *entered* that state
sbe_entry= {
    'istep 4.' : None,              # SBE entry
}
sbe_exit = {
    'SBE starting hostboot' : None,
#    'shutdown requested': error_pattern, # FIXME: too broad, see GH issue
#TODO: find all the hostboot / SBE error patterns we might need to care about.
}

# each expect table indicates when we've *entered* that state
hb_entry= {
    'Welcome to Hostboot' : None,   # hostboot entry
    '|ISTEP 6.4' : None,
}
hb_exit = {
    'ISTEP 21. 3' : None, # host start payload
}

skiboot_entry = {
    '] OPAL v6.' : None,
    '] OPAL v5.' : None, #
    '] SkiBoot' : None,  # old boot header
    '] OPAL skiboot-v' : None, # occurs semi-frequently
}
skiboot_exit = {
    '] INIT: Starting kernel at' : None,
}

pb_entry = {
    'Petitboot': None,
    'x=exit': None,
    '/ #': None,
#    'shutdown requested': error_pattern, # FIXME: too broad, see GH issue
    'login: ': missed_state,
#    'mon> ': xmon_callback,
#    'dracut:/#': dracut_callback,
#    'System shutting down with error status': guard_callback,
    'Aborting!': error_pattern,
}
pb_exit = {
    'login: ': None,
    '/ #': error_pattern,
    'mon> ': error_pattern,
#    'dracut:/#': dracut_callback,
}

login_entry = {
    'login: ': None,
    '/ #': error_pattern,
    'mon> ': error_pattern,
#    'dracut:/#': dracut_callback,
}
login_exit = {
    '# ' : None,
    # FIXME: Add other shell patterns
}

class OpSystem(BaseSystem):
    # ordered list of possible states for this system
    openpower_state_table = [
#        ConsoleState('off',  None,           1),
        # there's a bit before we hit skiboot_entry
#        ConsoleState('sbe',       sbe_entry,     60, sbe_exit,      60),
        ConsoleState('hostboot',  hb_entry,      30, hb_exit,      180),
        ConsoleState('skiboot',   skiboot_entry, 30, skiboot_exit,  60),
        ConsoleState('petitboot', pb_entry,      30, pb_exit,      120),
        ConsoleState('login',     login_entry,   30, login_exit,   180),
#        ConsoleState('os',        os_entry,      10, os_exit,       30),
    ]

    def __init__(self, host=None, console=None, pdu=None):
        super().__init__(host, console, pdu)

        # build our state table
        for s in self.openpower_state_table:
            self._add_state(s)

        # a list of error patterns to look for while expect()ing the
        # host console FIXME: these are in OpExpect currently, which is
        # dumb
        self.error_patterns = []
