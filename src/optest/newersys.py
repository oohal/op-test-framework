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

# called when we get to the login prompt when we wanted petitboot (i.e. missed PB)
def login_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
    log.warning(
        "\n\n *** OpTestSystem found the login prompt \"{}\" but this is unexpected, we will retry\n\n".format(kwargs['value']))
    # raise the WaitForIt exception to be bubbled back to recycle early rather than having to wait the full loop_max
    raise WaitForIt(expect_dict=self.petitboot_expect_table,
                    reconnect_count=-1)

# called when we get to petitboot, but wanted the login prompt (i.e. unwanted reboot)
def petitboot_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
    log.warning(
        "\n\n *** OpTestSystem found the petitboot prompt \"{}\" but this is unexpected, we will retry\n\n".format(kwargs['value']))
    raise WaitForIt(expect_dict=self.login_expect_table,
                    reconnect_count=-1)


# Hostboot IPL error, bummer
def hostboot_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
    self.state = OpSystemState.UNKNOWN_BAD
    self.stop = 1
    raise HostbootShutdown()

# we hit this when hostboot guards something out during boot.
# it should probably be non-fatal.
def guard_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
#        self.sys_sel_elist(dump=True)
    guard_exception = UnexpectedCase(
        state=self.state, message="We hit the guard_callback value={}, manually restart the system".format(kwargs['value']))
    self.state = OpSystemState.UNKNOWN_BAD
    self.stop = 1
    raise guard_exception

# kernel crash! Weeeeeeeeeeee
def xmon_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None} # can we replace this with dict({...}).update(kwargs)? or even .get()
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
    xmon_check_r = kwargs['my_r']
    xmon_value = kwargs['value']
    time.sleep(2)
    sys_pty = self.console.get_console()
    time.sleep(2)
    sys_pty.sendline("t")
    time.sleep(2)
    rc = sys_pty.expect(
        [".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
    xmon_backtrace = sys_pty.after
    sys_pty.sendline("r")
    time.sleep(2)
    rc = sys_pty.expect(
        [".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
    xmon_registers = sys_pty.after
    sys_pty.sendline("S")
    time.sleep(2)
    rc = sys_pty.expect(
        [".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
    xmon_special_registers = sys_pty.after
    sys_pty.sendline("e")
    time.sleep(2)
    rc = sys_pty.expect(
        [".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
    xmon_exception_registers = sys_pty.after

#        self.sys_sel_elist(dump=True) # hmm, suppose we can do that out of band?
    self.stop = 1

    my_msg = ('We hit the xmon_callback with \"{}\" backtrace=\n{}\n'
              ' registers=\n{}\n special_registers=\n{}\n'
              ' exception_registers=\n{}\n'
              .format(xmon_value,
                      xmon_backtrace,
                      xmon_registers,
                      xmon_special_registers,
                      xmon_exception_registers))
    xmon_exception = UnexpectedCase(state=self.state, message=my_msg)
    self.state = OpSystemState.UNKNOWN_BAD
    raise xmon_exception

def dracut_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]
    try:
        sys_pty = self.console.get_console()
        sys_pty.sendline('cat /run/initramfs/rdsosreport.txt')
    except Exception as err:
        log.warning("Could not get dracut failure messages:\n %s", err)
    self.state = OpSystemState.UNKNOWN_BAD
    self.stop = 1
    msg = ("We hit the dracut_callback value={}, "
           "manually restart the system\n".format(kwargs['value']))
    dracut_exception = UnexpectedCase(state=self.state, message=msg)
    raise dracut_exception

def skiboot_callback(self, **kwargs):
    default_vals = {'my_r': None, 'value': None}
    for key in default_vals:
        if key not in list(kwargs.keys()):
            kwargs[key] = default_vals[key]

#        self.sys_sel_elist(dump=True)
    skiboot_exception = UnexpectedCase(
        state=self.state, message="We hit the skiboot_callback value={}, manually restart the system".format(kwargs['value']))
    self.state = OpSystemState.UNKNOWN_BAD
    self.stop = 1
    raise skiboot_exception

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
    '/ #': None,
    'shutdown requested': self.hostboot_callback,
    'x=exit': None,
    'login: ': self.login_callback, # missed petitboot -> UNKNOWN_BAD
    'mon> ': self.xmon_callback,
    'dracut:/#': self.dracut_callback,
    'System shutting down with error status': self.guard_callback,
    'Aborting!': self.skiboot_callback,
}

login_expect_table = {
    'login: ': None,
    '/ #': self.petitboot_callback,
    'mon> ': self.xmon_callback,
    'dracut:/#': self.dracut_callback,
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

        # XXX: should setting this up be the job of the subclass?
        self.state_table = []
        self.state_dict = {}
        self.state_idx = {}

        # FIXME: the state table is system specific and should be done in the subclass
        for s in state_table:
            self._add_state(s)

        # a list of error patterns to look for while expect() the
        # host console
        self.error_patterns = []

        # tunables for customizations, put them here all together

        # ipmi versus ssh settings, sometimes tuning is needed based on type, so keeping split for tuning
        # to basically turn off reconnect based on stale buffers set threshold equal to watermark, e.g. 100
        if isinstance(self.console, OpTestIPMI.IPMIConsole):
            self.threshold_petitboot = 12  # stale buffer check
            # long enough to skip the refresh until kexec, stale buffers need to be jumped over
            self.threshold_login = 12
            self.petitboot_kicker = 0
            self.petitboot_refresh = 0  # petitboot menu cannot tolerate, cancels default boot
            self.petitboot_reconnect = 1
            self.login_refresh = 0
            # less reliable connections, ipmi act/deact does not trigger default boot cancel
            self.login_reconnect = 1
        else:
            self.threshold_petitboot = 12  # stale buffer check
            # long enough to skip the refresh until kexec, stale buffers need to be jumped over
            self.threshold_login = 12
            self.petitboot_kicker = 0
            self.petitboot_refresh = 0  # petitboot menu cannot tolerate, cancels default boot
            self.petitboot_reconnect = 1  # NEW ssh triggers default boot cancel, just saying
            self.login_refresh = 0
            self.login_reconnect = 1  # NEW ssh triggers default boot cancel, just saying


        # FIXME: document what these actually do

        # watermark is the loop counter (loop_max) used in conjunction with
        # timeout
        self.ipl_watermark = 100

        # watermark will automatically increase in case the loop is too short
        self.booting_watermark = 100
        self.kill_cord = 102  # just a ceiling on giving up
        # timeout is the expect timeout for each iteration

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

    # not required, they're only really useful if a PDU exists
    def bmc_power_off(self):
        raise NotImplementedError()
    def bmc_power_on(self):
        raise NotImplementedError()

    def collect_debug(self):
        pass


    ############################################################################
    # Console Wrangling
    #
    # Returns the OpTestConsole for the host
    #
    ############################################################################

    # return the raw console object, useful for wrangling expect
    def get_console(self):
        return self.console

    def run_command(self, cmd, timeout=60):
        return self.console.run_command(cmd, timeout)

    # this can probably go elsewhere...
    def skiboot_log_on_console(self):
        return True



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

    def poweroff(self, soft_first=True):
        ''' helper for powering off the host and reset our state tracking '''
        self.reset_states()

        self.host_power_off()
        if soft_first:
            for i in range(self.power_off_delay):
                if self.host_is_off():
                    return
                time.sleep(1)
            log.info("Timeout while powering off host. Yanking power now")

        # try a little harder...
        self.host_hard_power_off():
        for i in range(self.power_yank_delay):
            if self.host_is_off():
                return

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

    def wait_for_it(self, **kwargs):
        '''
        wait_for_it() - It waits for it.

        There's a few problems we need to deal with while expect()ing
        the console. The biggest is missing some event due to the
        disconnects or characters being dropped. This function
        tries to handle those as gracefully as possible.

        Situations we have to deal with:

        1) Being stuck at a login prompt. Getty does nothing unless you
           poke it, so we might have to. Sending a newline will generally
           refresh the prompt, but it might not.

        2) The host is non-responsive because the console died. Happens
           pretty frequently with certain BMC implementations and we can
           work around it to some extent by re-starting the console session.
           However, anything using op-test (i.e. tests) probably won't
           cope all that well.

        3) The host is non-responsive because it's dead. There's not much
           we can do it about it here other than raise an exception if we
           think it's happened. Frustratingly, this is also pretty hard
           to differentate from 2) so we need to try handle that before
           we escalate.

         TODO: In theory we could check with the BMC to see if there was
               a host checkstop to get confirmation. Won't catch all
               host-crashes, but it's probably worth handling

        4) Missing our patterns and ending up somewhere unexpected

           e.g. Going for PETITBOOT, and ending up at the host OS login
                prompt because the console disconnected.

        Again, not much we can do about this right here. The callbacks
        in the expect dictionary are used to handle these cases, but
        it does mean you need to know what the fail cases are in
        advance.
        '''

        args = {'expect_dict': None,
                'refresh': 1,
                'buffer_kicker': 1,
                'loop_max': 8,
                'threshold': 1,
                'reconnect': True,
                'max_reconnect': 5,
                'expect_timeout': 5} # seconds
        args.update(kwargs)

        err_match = [pexpect.TIMEOUT, pexpect.EOF]
        our_match = list(sorted(args['expect_dict'].keys()))
        expect = our_match + err_match

        # check console type and pass 5 to skip SMS menu when booting an LPAR
        #if isinstance(self.console, OpTestHMC.HMCConsole):
        #    sys_pty.sendline('5')
        #
        # FIXME: commented out to break the circular includes with OpTestHMC

        # we do not perform buffer_kicker here since it can cause changes to
        # things like the petitboot menu and default boot

        self.console.connect()
        if args['refresh']:
            sys_pty.sendcontrol('l')

        previous_before = 'emptyfirst'
        reconnect_count = 0
        timeout_count = 0
        stale_count = 0
        caller = str(inspect.stack()[1].function)

        for x in range(args['loop_max']):
            pty = self.console.pty  # preemptive in case EOF XXX: why's this needed?

            r = pty.expect(expect, args['expect_timeout'])
            if expect[r] in our_match:
                log.debug("WaitForIt: matched on {} {} ".format(r, expect[r]))
                matched = expect[r]

                callback = args['expect_dict'][matched]
                if callback:
                    callback(r, matched) # this will probably throw

                return r, reconnect_count

            elif expect[r] == pexpect.TIMEOUT:
                log.debug("WaitForIt: Timeout")
                timeout_count += 1

                # no new input means we might have hit one of our error cases
                if previous_before == pty.before:
                    if args['refresh']:
                        pty.sendcontrol('l')
                    if args['buffer_kicker']:
                        pty.sendline("\r")
                    stale_count += 1

                # if the console hasn't done anything for a while it
                # might have died (case 2)
                if stale_count % args['threshold'] == 0:
                    do_reconnect = True
            elif expect[r] == pexpect.EOF:
                log.debug("WaitForIt: EOF")
                log.debug("WaitForIt: patterns:")
                for p in our_match:
                    log.debug("WaitForIt: '''{}'''".format(p))
                log.debug("WaitForIt: pty.before[-100:]: {}".format(pty.before[-100:]))

                do_reconnect = True

            if do_reconnect:
                do_reconnect = False
                # if we hit max reconnects then either the system is dead
                # or the console completely unusable
                if args['reconnect'] and reconnect_count < args['max_reconnect']:
                    self.console.close()
                    self.console.connect()
                    reconnect_count += 1
                else:
                    raise "Console died while waiting_for_it" # FIXME: exception type

            log.debug("*** WaitForIt caller: {} state: {:2} -> {:2}"
                      .format(caller, self.state, self.target_state))
            log.debug("*** Current loop {:02} of {:02} Reconnects {:02}"
                      .format(x, args['loop_max'], reconnect_count))
            log.debug("*** WaitForIt expect timeout: {:02}s - Stale buffer check every {:02} times\n"
                      .format(args['threshold'], args['timeout']))
            log.debug("*** WaitForIt expect_patterns Expect Buffer ID = {}"
                      .format(sorted(args['expect_dict'].keys()), id(pty)))
            log.debug("*** WaitForIt Refresh={} Buffer Kicker={} - Kill Cord={:02}"
                      .format(args['refresh'], args['buffer_kicker'], self.kill_cord))


    def start_power_off(self):
        ''' initiates a host power off, doesn't touch the state machine '''
        # FIXME: should we set self.state here? dunno
        self.console.shell_mark_invalid()
        self.host_power_off()
        self.power_off_start_time = time.monotonic()

    # Expect wrangling to get into and out of petitboot
    def petitboot_exit_to_shell(self):
        sys_pty = self.console.get_console()
        log.debug("USING PES Expect Buffer ID={}".format(hex(id(sys_pty))))
        for i in range(3):
            sys_pty.send('x')
            pp = self.get_petitboot_prompt()
            if pp == 1:
                break
        if pp != 1:
            log.warning(
                "OpTestSystem detected something, tried to recover, but still we have a problem, retry")
            raise ConsoleSettings(before=sys_pty.before, after=sys_pty.after,
                                  msg="System at Petitboot Menu unable to exit to shell after retry")

    def get_petitboot_prompt(self):
        my_pp = 0
        sys_pty = self.console.get_console()
        log.debug("USING GPP Expect Buffer ID={}".format(hex(id(sys_pty))))
        sys_pty.sendline()
        pes_rc = sys_pty.expect(
            [".*#", ".*# $", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        if pes_rc in [0, 1]:
            if self.PS1_set != 1:
                self.SUDO_set = self.LOGIN_set = self.PS1_set = self.util.set_PS1(
                    self.console, sys_pty, self.util.build_prompt(self.prompt))
            # unblock in case connections are lost during state=4 the get_console/connect can properly setup again
            self.block_setup_term = 0
            self.previous_state = OpSystemState.PETITBOOT_SHELL  # preserve state
            my_pp = 1
        return my_pp

    def exit_petitboot_shell(self):
        sys_pty = self.console.get_console()
        log.debug("USING EPS 1 Expect Buffer ID={}".format(hex(id(sys_pty))))
        eps_rc = self.try_exit(sys_pty)
        if eps_rc == 0:  # Petitboot
            return
        else:  # we timed out or eof
            try:
                self.util.try_recover(self.console, counter=3)
                # if we get back here we're good and at the prompt
                # but we lost our sys_pty, so get a new one
                sys_pty = self.console.get_console()
                log.debug("USING EPS 2 Expect Buffer ID={}".format(
                    hex(id(sys_pty))))
                sys_pty.sendline()
                eps_rc = self.try_exit(sys_pty)
                if eps_rc == 0:  # Petitboot
                    return
                else:
                    raise RecoverFailed(before=sys_pty.before, after=sys_pty.after,
                                        msg="Unable to get the Petitboot prompt stage 3, we were trying to exit back to menu")
            except Exception as e:
                # who knows but keep on
                log.debug("EPS Exception={}".format(e))

    def try_exit(self, sys_pty):
        self.util.clear_state(self)
        log.debug("USING TE Expect Buffer ID={}".format(hex(id(sys_pty))))
        sys_pty.sendline()
        sys_pty.sendline("exit")
        rc_return = sys_pty.expect(
            ["Petitboot", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        log.debug("rc_return={}".format(rc_return))
        log.debug("sys_pty.before={}".format(sys_pty.before))
        log.debug("sys_pty.after={}".format(sys_pty.after))
        if rc_return == 0:
            return rc_return
        else:
            return -1

