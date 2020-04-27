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


class spawn(pexpect.spawn):

    def __init__(self, command, args=[], maxread=8000,
                 searchwindowsize=None, logfile=None, cwd=None, env=None,
                 ignore_sighup=False, echo=True, preexec_fn=None,
                 encoding='utf-8', codec_errors='ignore', dimensions=None,
                 failure_callback=None, failure_callback_data=None):
        self.command = command
        self.failure_callback = failure_callback
        self.failure_callback_data = failure_callback_data
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

    def set_system(self, system):
        self.op_test_system = system
        return

    def do_callback(self):
        # We set the system state to UNKNOWN_BAD as we want to have a path
        # to recover and run the next test, which is going to be to IPL
        # the box again.
        # We do this via a callback rather than any other method as that's
        # just a *lot* easier with current code structure
        if self.failure_callback:
            state = self.failure_callback(self.failure_callback_data)


    def handle_kernel_err(self, p):
        log = str(self.after)
        l = 0

        self.do_callback()

        # scrape the reset of the error message
        while l != 8:
            l = super(spawn, self).expect(["INFO: rcu_sched self-detected stall on CPU",
                                           "Watchdog .* Hard LOCKUP",
                                           "Sending IPI to other CPUs",
                                           ":mon>",
                                           "Rebooting in \d+ seconds",
                                           "Kernel panic - not syncing: Fatal exception",
                                           "Kernel panic - not syncing: Hard LOCKUP",
                                           "opal_cec_reboot2", pexpect.TIMEOUT],
                                          timeout=15)
            log = log + str(self.before) + str(self.after)
            if l in [2, 3, 4, 7]:
                # We know we have the end of the error message, so let's
                # stop here.
                break

        if "soft lockup" in p:
            raise KernelSoftLockup(state, log)
        if "hard lockup" in p.tolower():
            raise KernelHardLockup(state, log)
        if "kernel BUG at" in p:
            raise KernelBug(state, log)
        if "kernel panic" in p.tolower():
            if l == 2:
                raise KernelKdump(state, log)
            if l == 7:
                raise KernelFADUMP(state, log)
            raise KernelPanic(state, log)
        if "Oops" in p:
            raise KernelOOPS(state, log)

        raise KernelCrashUnknown(state, log)

    def handle_opal_err(self, is_assert, pty):
        self.do_callback()

        l = 0
        log = self.after
        l = super(spawn, self).expect(["boot_entry.*\r\n",
                                           "Initiated MPIPL", pexpect.TIMEOUT],
                                          timeout=10)
        log = log + self.before + self.after
        if is_assert:
           raise SkibootAssert(state, log)
        else:
            raise SkibootException(state, log)


    def handle_plat_error(self):
        self.do_callback()

        # Reboot due to HW core checkstop
        # Let's attempt to capture Hostboot output
        log = self.before + self.after
        try:
            l = super(spawn, self).expect("================================================",
                                          timeout=120)
            log = log + self.before + self.after
            l = super(spawn, self).expect(
                "System checkstop occurred during runtime on previous boot", timeout=30)
            log = log + self.before + self.after
            l = super(spawn, self).expect("================================================",
                                          timeout=60)
            log = log + self.before + self.after
            l = super(spawn, self).expect("ISTEP", timeout=20)
            log = log + self.before + self.after
        except pexpect.TIMEOUT as t:
            pass

        raise PlatformError(state, log)

    def qemu_err(self):
        raise CommandFailed(self.command, "????", -1)

    def expect(self, input_pattern, timeout=-1, searchwindowsize=-1):

        # HACK: just for now until I move this into OpTestSystem
        self.clear_patterns()


        qemu_err = lambda pty, pat: self.qemu_err()
        self.add_pattern(qemu_err, "qemu: could find kernel")

        kern_err = lambda pty, pat: self.handle_kernel_err(p, pat)
        self.add_pattern(kern_err, "INFO: rcu_sched self-detected stall on CPU")
        self.add_pattern(kern_err, "kernel BUG at")
        self.add_pattern(kern_err, "Kernel panic")
        self.add_pattern(kern_err, "Oops: Kernel access of bad area")

        self.add_pattern(kern_err, "Watchdog .* Hard LOCKUP")
        self.add_pattern(kern_err, "watchdog: .* detected hard LOCKUP on other CPUs")
        self.add_pattern(kern_err, "Watchdog .* detected Hard LOCKUP other CPUS")
        self.add_pattern(kern_err, "watchdog: BUG: soft lockup")

        opal_assert = lambda pty, pat: self.handle_opal_err(p, True)
        self.add_pattern(opal_assert, "\[[0-9. ]+,0\] Assert fail:")

        opal_ex = lambda pty, pat: self.handle_opal_err(p, False)
        self.add_pattern(opal_ex, "\[[0-9. ]+,[0-9]\] Unexpected exception")
        self.add_pattern(opal_ex, "OPAL exiting with locks held")
        self.add_pattern(opal_ex, "LOCK ERROR: Releasing lock we don't hold")

        plat_err = lambda pty, pat: self.handle_plat_err()
        self.add_pattern(plat_err, "OPAL: Reboot requested due to Platform error.")


        # FIXME: fix this once the above is done
        if isinstance(input_pattern, list):
            patterns = self.patterns + input_pattern
            cb = self.cb + [None for x in input_pattern]
        else:
            patterns = self.patterns + [pattern]
            cb = self.cb + [None]

        r = super(spawn, self).expect(patterns,
                                      timeout=timeout,
                                      searchwindowsize=searchwindowsize)

        if r in [pexpect.EOF, pexpect.TIMEOUT]:
            return r


        # call the callback for this pattern, assuming we have one
        if cb[r]:
            cb[r](pty, patterns[r]) # this should throw
            raise Exception("OpExpect callback returned, don't do that")

        return r - len(self.patterns)
