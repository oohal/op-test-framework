#!/usr/bin/env python3
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2017
# [+] International Business Machines Corp.
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

"""
The OpExpect module is a wrapper around the standard Python pexpect module
that will *always* look for certain error conditions for OpenPOWER machines.

This is to enable op-test test cases to fail *quickly* in the event of errors
such as kernel panics, RCU stalls, machine checks, firmware crashes etc.

In the event of error, the failure_callback function will be called, which
typically will be set up to set the machine state to UNKNOWN, so that when
the next test starts executing, we re-IPL the system to get back to a clean
slate.

When developing test cases, use OpExpect over pexpect. If you *intend* for
certain error conditions to occur, you can catch the exceptions that OpExpect
throws.
"""

import pexpect
from .Exceptions import *

def handle_kernel_err(pty, p):
    log = str(pty.after)
    l = 0

    # scrape the reset of the error message
    while l != 8:
        l = super(spawn, pty).expect([
                 "INFO: rcu_sched self-detected stall on CPU",
                 "Watchdog .* Hard LOCKUP",
                 "Sending IPI to other CPUs",
                 ":mon>",
                 "Rebooting in \d+ seconds",
                 "Kernel panic - not syncing: Fatal exception",
                 "Kernel panic - not syncing: Hard LOCKUP",
                 "opal_cec_reboot2", pexpect.TIMEOUT,
                 ], timeout=15)
        log = log + str(pty.before) + str(pty.after)
        if l in [2, 3, 4, 7]:
            # We know we have the end of the error message, so let's
            # stop here.
            break

    if "soft lockup" in p:
        raise KernelSoftLockup(log)
    if "hard lockup" in p.tolower():
        raise KernelHardLockup(log)
    if "kernel BUG at" in p:
        raise KernelBug(log)
    if "kernel panic" in p.tolower():
        if l == 2:
            raise KernelKdump(log)
        if l == 7:
            raise KernelFADUMP(log)
        raise KernelPanic(log)
    if "Oops" in p:
        raise KernelOOPS(log)

    raise KernelCrashUnknown(log)

def handle_opal_err(pty, is_assert):
    log = pty.after

    # hmm,  might need to move this elsewhere
    l = super(spawn, pty).expect(["boot_entry.*\r\n",
                                   "Initiated MPIPL", pexpect.TIMEOUT],
                                   timeout=10)
    log = log + pty.before + pty.after
    if is_assert:
       raise SkibootAssert(log)
    else:
        raise SkibootException(log)


def handle_plat_err(pty, exp):
    # Reboot due to HW core checkstop
    # Let's attempt to capture Hostboot output
    log = pty.before + pty.after
    try:
        l = super(spawn, pty).expect("================================================",
                                      timeout=120)
        log = log + pty.before + pty.after
        l = super(spawn, pty).expect(
            "System checkstop occurred during runtime on previous boot", timeout=30)
        log = log + pty.before + pty.after
        l = super(spawn, pty).expect("================================================",
                                      timeout=60)
        log = log + pty.before + pty.after
        l = super(spawn, pty).expect("ISTEP", timeout=20)
        log = log + pty.before + pty.after
    except pexpect.TIMEOUT as t:
        pass

    raise PlatformError(log)

def qemu_err(pty):
    raise CommandFailed(pty.command, "????", -1)

class spawn(pexpect.spawn):
    def __init__(self, command, args=[], maxread=8000,
                 searchwindowsize=None, logfile=None, cwd=None, env=None,
                 ignore_sighup=False, echo=True, preexec_fn=None,
                 encoding='utf-8', codec_errors='ignore', dimensions=None,
                 failure_callback=None, failure_callback_data=None):


        # deprecated
        assert not failure_callback
        assert not failure_callback_data

        self.command = command
        super(spawn, self).__init__(command, args=args,
                                    maxread=maxread,
                                    searchwindowsize=searchwindowsize,
                                    logfile=logfile,
                                    cwd=cwd, env=env,
                                    ignore_sighup=ignore_sighup,
                                    encoding=encoding,
                                    codec_errors=codec_errors)
        self.patterns = []

    def add_pattern(self, cb, pattern):
        self.patterns.append(pattern)
        self.cb.append(cb)

    def clear_patterns(self):
        self.patterns = []
        self.cb = []

    def expect(self, input_pattern, timeout=-1, searchwindowsize=-1):
        # HACK: just for now until I move this into OpTestSystem
        self.clear_patterns()

        qemu_err = lambda pty, pat: qemu_err(pty, pat)
        self.add_pattern(qemu_err, "qemu: could find kernel")

        kern_err = lambda pty, pat: handle_kernel_err(pty, pat)
        self.add_pattern(kern_err, "INFO: rcu_sched self-detected stall on CPU")
        self.add_pattern(kern_err, "kernel BUG at")
        self.add_pattern(kern_err, "Kernel panic")
        self.add_pattern(kern_err, "Oops: Kernel access of bad area")

        self.add_pattern(kern_err, "Watchdog .* Hard LOCKUP")
        self.add_pattern(kern_err, "watchdog: .* detected hard LOCKUP on other CPUs")
        self.add_pattern(kern_err, "Watchdog .* detected Hard LOCKUP other CPUS")
        self.add_pattern(kern_err, "watchdog: BUG: soft lockup")

        opal_assert = lambda pty, pat: handle_opal_err(pty, True)
        self.add_pattern(opal_assert, "\[[0-9. ]+,0\] Assert fail:")

        opal_ex = lambda pty, pat: handle_opal_err(pty, False)
        self.add_pattern(opal_ex, "\[[0-9. ]+,[0-9]\] Unexpected exception")
        self.add_pattern(opal_ex, "OPAL exiting with locks held")
        self.add_pattern(opal_ex, "LOCK ERROR: Releasing lock we don't hold")

        plat_err = lambda pty, pat: handle_plat_err(pty, pat)
        self.add_pattern(plat_err, "OPAL: Reboot requested due to Platform error.")


        # FIXME: fix this once the above is done
        if isinstance(input_pattern, list):
            patterns = self.patterns + input_pattern
            cb = self.cb + [None for x in input_pattern]
        else:
            patterns = self.patterns + [input_pattern]
            cb = self.cb + [None]

        r = super(spawn, self).expect(patterns,
                                      timeout=timeout,
                                      searchwindowsize=searchwindowsize)

        if r in [pexpect.EOF, pexpect.TIMEOUT]:
            return r


        # call the callback for this pattern, assuming we have one
        if cb[r]:
            cb[r](self, patterns[r]) # this should throw
            raise Exception("OpExpect callback returned, don't do that")

        return r - len(self.patterns)


class PetitbootHelper():
    ''' helper functions for driving petitboot '''
    def __init__(self, system):
        self.sys = system
        # verify that we're actually at petitboot

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

    def get_my_ip_from_host_perspective(self):
        raw_pty = self.console.get_console()
        # run any command to get the prompt setup
        hostname_output = self.console.run_command("hostname -i")
        log.debug("hostname_output={}".format(hostname_output))
        if len(hostname_output) >= 1:
            my_ip = hostname_output[0]
        else:
            my_ip = None
        log.debug("hostname_output to my_ip={}".format(my_ip))
        port = 12340
        my_ip = None
        try:
            if self.get_state() == OpSystemState.PETITBOOT_SHELL:
                raw_pty.send("nc -l -p %u -v -e /bin/true\n" % port)
            else:
                raw_pty.send("nc -l -p %u -v\n" % port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            time.sleep(0.5)
            log.debug("If UNABLE to ping, check DNS or multihome, hostname={} port={}"
                      .format(self.host().hostname(), port))
            log.debug("# Connecting to %s:%u" % (self.host().hostname(), port))
            sock.settimeout(30)
            try:
                sock.connect((self.host().hostname(), port))
            except socket.error as e:
                log.debug("socket.error Exception={}".format(e))
                if e.errno == errno.ECONNRESET or e.errno == errno.EPIPE:
                    log.debug("socket.error Exception expected={}".format(e))
                    pass
                else:
                    log.debug("socket.error raise  Exception={}".format(e))
                    raise e
            try:
                sock.send('Hello World!'.encode())
                log.debug("sock send Hello World")
                sock.close()
                log.debug("sock close")
            except socket.error as e:
                log.debug("socket.error send close Exception={}".format(e))
                if e.errno == errno.ECONNRESET or e.errno == errno.EPIPE:
                    log.debug(
                        "socket.error Exception send close expected={}".format(e))
                    pass
                else:
                    log.debug(
                        "socket.error raise send close Exception={}".format(e))
                    raise e
            rc = raw_pty.expect(
                ['Connection from ', pexpect.TIMEOUT, pexpect.EOF])
            log.debug("Connection from rc={}".format(rc))
            rc = raw_pty.expect([':', ' ', pexpect.TIMEOUT, pexpect.EOF])
            log.debug("Colon rc={}".format(rc))
            my_ip = raw_pty.before
            log.debug("raw_pty before={} raw_pty after={}".format(
                raw_pty.before, raw_pty.after))
            raw_pty.expect('\n')
            raw_pty.expect('#')
            log.debug(
                "Connection from: my_ip={}, this is the op-test box".format(my_ip))
            if my_ip is not None:
                # need to investigate multihomed boxes more
                just_ip = socket.gethostbyname(my_ip)
                log.debug("just_ip={}".format(just_ip))
            return my_ip
        except Exception as e:  # Looks like older nc does not support -v, lets fallback
            log.debug("Processing in Exception path, e={}".format(e))
            raw_pty.sendcontrol('c')  # to avoid incase nc command hangs
            time.sleep(2)  # give it time to recover
            try:
                ip = subprocess.check_output(['hostname', '-i']).decode('utf-8').strip()
                ip_lst = subprocess.check_output(['hostname', '-I']).decode('utf-8').strip().split()
                # Let's validate the IP
                for item in ip_lst:
                    if item == ip:
                        my_ip = ip
                        break
                if not my_ip:
                    if len(ip_lst) == 1:
                        my_ip = ip_lst[0]
                    else:
                        log.warning("Unable to get server ip, "
                                    "hostname -i does not provide valid IP, "
                                    "correct and proceed with installation")
            except subprocess.CalledProcessError as e:
                log.warning("Unable to get server ip, hostname -i/-I "
                            "commands not supported in server")

        return my_ip
