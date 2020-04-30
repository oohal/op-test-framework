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


class OpSystemState():
    '''
    This class is used as an enum as to what state op-test *thinks* the host is in.
    These states are used to drive a state machine in OpTestSystem.
    '''
    UNKNOWN = 0
    OFF = 1
    IPLing = 2
    PETITBOOT = 3
    PETITBOOT_SHELL = 4
    BOOTING = 5
    OS = 6
    POWERING_OFF = 7
    UNKNOWN_BAD = 8  # special case, use set_state to place system in hold for later goto
    # BMC_OFF
    # BMC_BOOTING


class OpTestSystem(object):
    def __init__(self,
                 host=None,
                 console=None,                 # subclasses should pass this up
                 pdu=None,                     # pdu for this system (if it has one)
                 trydetect=False,              # determine whether we try to detect the system state
                                               # or just force a power cycle
                 state=OpSystemState.UNKNOWN): # where do we pass in the pdu / serial cons objects?

        self.cv_HOST = host
        self.console = console
        self.stop = 0
        self.previous_state = OpSystemState.UNKNOWN
        self.state = OpSystemState.UNKNOWN

        self.should_detect = trydetect

        # When we leave the PETITBOOT and/or OS state.
        self.setup_prompt = False

        # dictionary used in sorted order
        # column 1 is the string, column 2 is the action
        # normally None is the action, otherwise a handler mostly used for exceptions

        self.petitboot_expect_table = {
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

        self.login_expect_table = {
            'login: ': None,
            '/ #': self.petitboot_callback,
            'mon> ': self.xmon_callback,
            'dracut:/#': self.dracut_callback,
        }

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

        # watermark is the loop counter (loop_max) used in conjunction with timeout
        # timeout is the expect timeout for each iteration
        # watermark will automatically increase in case the loop is too short
        self.ipl_watermark = 100
        self.booting_watermark = 100
        self.kill_cord = 102  # just a ceiling on giving up

        # We have a state machine for going in between states of the system
        # initially, everything in UNKNOWN, so we reset things.
        # UNKNOWN is used to flag the system to auto-detect the state if
        # possible to efficiently achieve state transitions.
        # But, we allow setting an initial state if you, say, need to
        # run against an already IPLed system
        self.state = state
        self.stateHandlers = {}
        self.stateHandlers[OpSystemState.UNKNOWN] = self.run_UNKNOWN
        self.stateHandlers[OpSystemState.OFF] = self.run_OFF
        self.stateHandlers[OpSystemState.IPLing] = self.run_IPLing
        self.stateHandlers[OpSystemState.PETITBOOT] = self.run_PETITBOOT
        self.stateHandlers[OpSystemState.PETITBOOT_SHELL] = self.run_PETITBOOT_SHELL
        self.stateHandlers[OpSystemState.BOOTING] = self.run_BOOTING
        self.stateHandlers[OpSystemState.OS] = self.run_OS
        self.stateHandlers[OpSystemState.POWERING_OFF] = self.run_POWERING_OFF
        self.stateHandlers[OpSystemState.UNKNOWN_BAD] = self.run_UNKNOWN

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
        if self.state not in [OpSystemState.PETITBOOT_SHELL, OpSystemState.OS]:
            raise RuntimeError("Can't run host commands in this state {}")
        return self.console.run_command(cmd, timeout)

    # this can probably go elsewhere...
    def skiboot_log_on_console(self):
        return True

    ############################################################################
    #
    # System state tracking circus. This only works well for PowerNV systems
    # at the moment. Eventually we need to generalise it a bit.
    #
    ############################################################################

    # tries to determine the state of the system
    # we could do this a part of system init, dunno
    def probe(self):
        raise NotImplementedError()
        
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


    class SysState():
        def __init__(self, name, patterns, timeout, interrupt):
            self.name = name
            self.patterns = patterns
            self.timeout = timeout
            self.interrupt = interrupt

    # ordered list of possible states for this system
    state_table = [
            SysState('sbe',       sbe_patterns), # tricky since not all systems have SBE output
            SysState('hostboot',   hb_patterns, 120),
            SysState('skiboot',   ski_patterns  60),
            SysState('petitboot',  pb_patterns, 60),
            SysState('login',   login_patterns, 180), # network cards suck
            SysState('os',         os_patterns, 30),
    ]

    def waitfor(self, state):
        if state not in self.states:
            raise ValueError("No such state?")
        if self.visited[state]:
            raise ValueError('State already visited')

        for index in range(len(self.state_table)):
            s = self.state_table[index]
            if s.name == target_state:
                break

        # console retry logic goes here
        self.console.expect(s.patterns, timeout=s.timeout)

        # backannotate all previous states as visited
        for i in range(index):
            self.visited[i] = True
        # can we verify our state some how?

    def waitat(self, target):
        if not self.state_dict[target].interrupt:
            raise ValueError("state can't be waited at")

        self.waitfor(target)
        self.state_dict[target].interrupt()
    # FIXME: Need an error table in addition.


    # FIXME: need to pick up non-xmon kernel crashes too
    def set_state(self, new_state):
        self.state = new_state

    def goto_state(self, target_state):
        # only perform detection when incoming state is UNKNOWN
        # if user overrides from command line and machine not at desired state can lead to exceptions
        self.target_state = target_state # used in WaitForIt

        if (self.state == OpSystemState.UNKNOWN):
            if self.should_detect:
                log.debug("OpTestSystem Trying to detect system state...")
                self.state = self.detect_state(target_state)
                log.debug("OpTestSystem Detected state %s" % (self.state))

        log.debug("OpTestSystem START STATE: %s (target %s)" %
                  (self.state, target_state))

        while True:
            log.debug('OpTestSystem {} -> {}'.format(self.state, self.target_state))
            # if we've managed to re-enter the unknown state something is broken
            # so bail here.
            if self.state == OpSystemState.UNKNOWN:
                self.stop = 1
                msg = '''OpTestSystem something set the system to UNKNOWN, check the logs for details, we will be stopping the system'''
                raise UnknownStateTransition(state=self.state, message=(msg))

            # might happen if something caught the above even though it shouldn't
            if self.stop == 1:
                raise StoppingSystem()

            # crank the state machine towards out goal
            self.state = self.stateHandlers[self.state](target_state)
 
            # log transitions
            if self.previous_state != self.state:
                self.console.shell_mark_invalid()
                self.previous_state = self.state
                log.debug("OpTestSystem TRANSITIONED TO: %s" % (self.state))

            if self.state == self.target_state:
                break

        # If we haven't checked for dangerous NVRAM options yet and
        # checking won't disrupt the test, do so now.
        #    if self.conf.nvram_debug_opts is None and state in [OpSystemState.PETITBOOT_SHELL, OpSystemState.OS]:
        #        self.util.check_nvram_options(self.console)
        # FIXME: move this elsewhere


    def detect_state(self, target_state):
        if not self.host_power_is_on():
            log.info("Detected powered off system")
            self.previous_state = OpSystemState.OFF # use set_state?
            return OpSystemState.OFF

        # try clear the input buffer to start with
        self.console.pty.sendcontrol('u')
        self.console.pty.sendline()

        # try a newline
        self.console.pty.sendline()
        detected = self.try_detect_state(target_state)
        if detected != OpSystemState.UNKNOWN:
            return detected

        # try clear the screen
        self.console.pty.sendcontrol('l')
        detected = self.try_detect_state(target_state)
        if detected != OpSystemState.UNKNOWN:
            return detected

        # still nothing? reboot time
        self.start_power_off()
        return OpSystemState.POWERING_OFF

    def try_detect_state(self, target_state, reboot):
        r = self.console.pty.expect(["x=exit", "Petitboot",
                                     ".*#", ".*\\$",
                                     "login:",
                                     pexpect.TIMEOUT, pexpect.EOF],
                                     timeout=1)

        if r in [0, 1]: # petitboot menu
            if target_state == OpSystemState.PETITBOOT:
                return OpSystemState.PETITBOOT

            elif target_state == OpSystemState.PETITBOOT_SHELL:
                self.petitboot_exit_to_shell()
                self.console.setup_shell()
                return OpSystemState.PETITBOOT_SHELL

        elif r in [2, 3]: # shell prompt!
            # FIXME: use uname -a
            self.console.setup_shell()

            # FIXME: replace this with a run_command
            detect_state = self.check_kernel_for_openpower()

            if (detect_state == target_state):
                self.previous_state = detect_state  # preserve state XXX: What's this doing?
                return detect_state
        
            # If we're targeting petitboot and we're in the OS then we'll have
            # to reboot. We also need to from petitboot since we've probably
            # paused the autoboot and petitboot won't resume it.
            self.start_power_off()
            return OpSystemState.POWERING_OFF

        elif r == 4: # login prompt
            if (target_state == OpSystemState.OS):
                self.console.handle_login()
                self.console.setup_shell()
                return OpSystemState.OS

        # error / no response
        return OpSystemState.UNKNOWN

    # check the kernel version string for -openpower, since that indicates
    # we're in petitboot
    def check_kernel_for_openpower(self):
        sys_pty.sendline()
        rc = sys_pty.expect(["x=exit", "Petitboot", ".*#", ".*\\$",
                             "login:", pexpect.TIMEOUT, pexpect.EOF], timeout=5)
        if rc in [0, 1, 5, 6]:
            # we really should not have arrived in here and not much we can do
            return OpSystemState.UNKNOWN

        sys_pty.sendline("cat /proc/version | grep openpower; echo $?")
        time.sleep(0.2)
        rc = sys_pty.expect(
            [self.expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=1)
        if rc == 0:
            echo_output = sys_pty.before
            try:
                echo_rc = int(echo_output.splitlines()[-1])
            except Exception as e:
                # most likely cause is running while booting unknowlingly
                return OpSystemState.UNKNOWN
            if (echo_rc == 0):
                self.previous_state = OpSystemState.PETITBOOT_SHELL
                return OpSystemState.PETITBOOT_SHELL
            elif echo_rc == 1:
                self.previous_state = OpSystemState.OS
                return OpSystemState.OS
            else:
                return OpSystemState.UNKNOWN
        else:  # TIMEOUT EOF from cat
            return OpSystemState.UNKNOWN


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

    def run_UNKNOWN(self, target_state):
        self.start_power_off()
        return OpSystemState.POWERING_OFF

    def run_OFF(self, target_state):
        if target_state == OpSystemState.OFF:
            return OpSystemState.OFF

        # going to need a way to ensure this is cleared.
        # we might want to make that a system specific thing and have it
        # nuke any overrides, put back default FW, etc. This is just one
        # of many things that would screw up booting...
        #
        # if target_state == OpSystemState.OS:
        #   clear any boot overrides since they could leave
        #   us stuck in petitboot
        #    self.sys_set_bootdev_no_override()
        #
        # set the bootdev so we stop in petitboot.
        #if target_state in [OpSystemState.PETITBOOT, OpSystemState.PETITBOOT_SHELL]:
        #    self.sys_set_bootdev_setup()

        # We clear any possible errors at this stage
        #self.sys_sdr_clear()

        # Only retry once
        # FIXME: Jank
        r = self.host_power_on()
        if r == BMC_CONST.FW_FAILED:
            r = self.host_power_on()
            if r == BMC_CONST.FW_FAILED:
                raise 'Failed powering on system'
        return OpSystemState.IPLing

    def run_IPLing(self, target_state):
        if target_state == OpSystemState.OFF:
            self.start_power_off()
            return OpSystemState.POWERING_OFF

        try:
            petitboot_expect_table = {
                'Petitboot'          : None,
                '/ #'                : None,
                'x=exit'             : None,
                'shutdown requested' : self.hostboot_callback,
                'login: ': self.login_callback,
                'mon> ': self.xmon_callback,
                'dracut:/#': self.dracut_callback,
                'System shutting down with error status': self.guard_callback,
                'Aborting!': self.skiboot_callback,
            }

            # if petitboot cannot be reached it will automatically increase the
            # watermark and retry see the tunables ipl_watermark and ipl_timeout
            # for customization for extra long boot cycles for debugging, etc
            petit_r, petit_reconnect = self.wait_for_it(
                                            expect_dict=petitboot_expect_table,
                                            reconnect=self.petitboot_reconnect,
                                            buffer_kicker=self.petitboot_kicker,
                                            threshold=self.threshold_petitboot,
                                            refresh=self.petitboot_refresh,
                                            loop_max=self.ipl_watermark)
        except HostbootShutdown as e:
            log.error(e)
#            self.sys_sel_check()
            raise e
        except (WaitForIt, HTTPCheck) as e:
            if self.ipl_watermark < self.kill_cord:
                self.ipl_watermark += 1
                log.warning("OpTestSystem UNABLE TO REACH PETITBOOT or we missed it"
                            "- \"{}\", increasing ipl_watermark for loop_max to {},"
                            " will re-IPL for another try".format(e, self.ipl_watermark))
                return OpSystemState.UNKNOWN_BAD # XXX: raise?

            else:
                self.stop = 1
                log.error("OpTestSystem has reached the limit on re-IPL'ing, stopping")
                return OpSystemState.UNKNOWN # XXX: Raise?

        except Exception as e:
            self.stop = 1  # Exceptions like in OpExpect Assert fail
            msg = ("OpTestSystem in run_IPLing and the Exception=\n\"{}\"\n caused the system to"
                      " go to UNKNOWN_BAD and the system will be stopping.".format(e))

            self.state = OpSystemState.UNKNOWN_BAD
            raise e # UnknownStateTransition(state=self.state, message=msg)

        if petit_r != -1:
            # Once reached to petitboot check for any SEL events
#            self.sys_sel_check()
            return OpSystemState.PETITBOOT

    def run_PETITBOOT(self, target_state):
        if target_state == OpSystemState.PETITBOOT:
            # verify that we are at the petitboot menu
            self.petitboot_exit_to_shell()
            self.exit_petitboot_shell()
            return OpSystemState.PETITBOOT

        if target_state == OpSystemState.PETITBOOT_SHELL:
            self.petitboot_exit_to_shell()
            return OpSystemState.PETITBOOT_SHELL

        if target_state == OpSystemState.OFF:
            self.start_power_off()
            return OpSystemState.POWERING_OFF

        # FIXME: drive petitboot to make sure this actuall happens
        if target_state == OpSystemState.OS:
            return OpSystemState.BOOTING

        raise UnknownStateTransition(
            state=self.state, message="OpTestSystem in run_PETITBOOT and something caused the system to go to UNKNOWN")

    def run_PETITBOOT_SHELL(self, target_state):
        if target_state == OpSystemState.PETITBOOT_SHELL:
            # verify that we are at the petitboot shell
            self.get_petitboot_prompt()
            return OpSystemState.PETITBOOT_SHELL

        if target_state == OpSystemState.PETITBOOT:
            self.exit_petitboot_shell()
            return OpSystemState.PETITBOOT

        self.start_power_off()
        return OpSystemState.POWERING_OFF

    def run_BOOTING(self, target_state):
        try:
            login_expect_table = {
                'login: '   : None,
                '/ #'       : self.petitboot_callback,
                'mon> '     : self.xmon_callback,
                'dracut:/#' : self.dracut_callback,
            }

            # if login cannot be reached it will automatically increase the
            # watermark and retry see the tunables booting_watermark and
            # booting_timeout for customization for extra long boot cycles
            # for debugging, etc
            login_r, login_reconnect = self.wait_for_it(
                                            expect_dict    = login_expect_table,
                                            reconnect      = self.login_reconnect,
                                            threshold      = self.threshold_login,
                                            refresh        = self.login_refresh,
                                            loop_max       = self.booting_watermark)
        # thrown from petitboot_callback, and login_callback
        except WaitForIt as e:
            if self.booting_watermark < self.kill_cord:
                self.booting_watermark += 1
                log.warning("OpTestSystem UNABLE TO REACH LOGIN or we missed it - \"{}\", increasing booting_watermark for loop_max to {},"
                            " will re-IPL for another try".format(e, self.booting_watermark))
                return OpSystemState.UNKNOWN_BAD
            else:
                log.error(
                    "OpTestSystem has reached the limit on re-IPL'ing to try to recover, we will be stopping")
                return OpSystemState.UNKNOWN
        except Exception as e:
            self.stop = 1  # hits like in OpExpect Assert fail
            self.state = OpSystemState.UNKNOWN_BAD
            raise e

        if login_r != -1:
            return OpSystemState.OS

    def run_OS(self, target_state):
        # FIXME: verify that we're actually at the OS. We might want to also
        # split out the "OS" state from a "waiting for login" state
        if target_state == OpSystemState.OS:
            return OpSystemState.OS

        self.start_power_off()
        return OpSystemState.POWERING_OFF

    def start_power_off(self):
        ''' initiates a host power off, doesn't touch the state machine '''
        # FIXME: should we set self.state here? dunno
        self.console.shell_mark_invalid()
        self.host_power_off()
        self.power_off_start_time = time.monotonic()

    def run_POWERING_OFF(self, target_state):
        # FIXME: Because this isn't watching the host console you get no output
        # until something starts looking at it again. Make this poll the power
        # status and drive expect with a low timeout so it's less crap.
        #
        # FIXME: use the time saved above to implement a timeout
        rc = int(self.sys_wait_for_standby_state(BMC_CONST.SYSTEM_STANDBY_STATE_DELAY))
        if rc == BMC_CONST.FW_SUCCESS:
            msg = "System is in standby/Soft-off state"
        elif rc == BMC_CONST.FW_PARAMETER:
            msg = "Host Status sensor is not available/Skipping stand-by state check"
        else:
            raise OpTestError("System failed to reach standby/Soft-off state")
        log.info(msg)

        return OpSystemState.OFF


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

