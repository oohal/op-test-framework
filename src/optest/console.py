#!/usr/bin/env python3
# encoding=utf8
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/common/SerialConsole.py $
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2019
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

'''
OpTestConsole
-------------

Generic interface for a host system console. This just specifies the interface.
Get a serial console and use it like an IPMI one. This basicly the same as
pxssh, but it works on things other than SSH Sessions too.

Most of the code in here is helpers for interacting with the system under
test (e.g. shell setup for pexpect, etc.

Connecting / Disconnecting from the actual console driver is handled by the
actual drivers which inherit off this.
'''

import random
import time
import sys
import os
import re

import pexpect
from .exceptions import CommandFailed, OpTestError

from . import opexpect
from . import logger
log = logger.optest_logger_glob.get_logger(__name__)

class ConsoleDisconnect(Exception):
    pass

class ConsoleState():
    DISCONNECTED = 0
    CONNECTED = 1

# FIXME: what should that log file be by default? Global logger?
class Console():
    def __init__(self, logfile=sys.stdout, prompt=None, disable_echo=False):
        self.state = ConsoleState.DISCONNECTED

        self.prompt = self.build_prompt(prompt)
        self.expect_prompt = self.prompt
#        self.expect_prompt = self.build_prompt(prompt) + " $" # the shell adds $ to the end
        self.logfile = logfile

        # populated by the console driver when .connect() is called
        self.pty = None

        # It's up to the caller to do setup_term() before trying to use
        # .run_command() and friends. Any of the helpers which depend
        # on the terminal being configured will barf if this is false.
        self.shell_setup_done = False

        # set of bonus expect patterns that are used on this console.
        # this is mainly so the System component can watch for things
        # like kernel panics while commands are being run on the host
        # console
        self.error_patterns = []


        self.disable_stty_echo = disable_echo

    # connection tracking is up to the derived class to implement
    def connect(self):
        ''' connect the console and return the raw pty object '''
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def is_connected(self): # -> Bool
        raise NotImplementedError()


    # XXX: is there any point to this?
    def build_prompt(self, prompt=None):
        # WARNING: this gets sent to a shell, which executes it so whatever
        # pattern we specify here needs to remain the same in all cases.
        # i.e. no special chars, no spaces
        if prompt:
            built_prompt = prompt
        else:
            built_prompt = "console-expect1" # FIXME: that # is a bug waiting to happen

        return built_prompt

    def shell_mark_invalid(self):
        self.shell_setup_done = False

    def shell_setup(self):
        patterns = [self.prompt, pexpect.TIMEOUT, pexpect.EOF]

        self.pty.sendline('unset HISTFILE;') # FIXME: does this persist across the exec below?
        self.pty.sendline("which sh && exec sh --norc --noprofile")

        # FIXME: do we even not have stty?
        self.pty.sendline("which stty && stty cols 300; which stty && stty rows 30;")

        # This is mainly for mambo where we can get two echos. One echo comes
        # from the simulated system and another comes from the simulator
        # itself.
        if self.disable_stty_echo:
            self.pty.sendline("which stty && stty -echo;")

        self.pty.sendline("export LANG=C;")

        # Clear any any accumulated output before we check for our new prompt.
        # This needed because if we come into a system that just happens to
        # have the prompt already configured (e.g. resuming an op-test run)
        # the expect() here would match on the prompts which are displayed
        # after running each command above
        #
        # see test_console_resetup in selftests for an example
#        unique = "# {}".format(random.randint(0,0xffffffff))
#        self.pty.sendline(unique)
#        rc = self.pty.expect([unique, pexpect.EOF], timeout=5)

        # now setup the prompt
        self.pty.sendline('PS1={}'.format(self.prompt))
        rc = self.pty.expect([self.prompt, pexpect.EOF], timeout=1) # matches on the echoed output of sendline()
        rc = self.pty.expect([self.prompt, pexpect.EOF], timeout=1) # matches the actual prompt

        if rc != 0:
            raise ConsoleSettings(before=pty.before, after=pty.after,
                                  msg="Problem with logging in. Probably a "
                                      "connection or credential issue")
            # FIXME: uncomment later           self.get_versions()

        log.debug("Shell prompt set to: {}".format(self.expect_prompt))
        self.shell_setup_done = True

    def handle_login(self, username, password, timeout=20):
        ''' drives a login prompt to get a shell '''

        # cases we need to watch for:
        # 1. A shell prompt  - already logged in?
        # 2. A login prompt  - write username in
        # 3. Password prompt - write in password
        # 4. timeout         - something's broken
        #
        # There's a few weird edge case states to keep in mind
        # too. e.g. for users with no password we go straight
        # to the shell prompt.

        patterns = ['login: ', r"[Pp]assword:"]
        shell_patterns = [".*#$", ".*# $", ".*\\$", "~ #"]

        ex = patterns + shell_patterns + [pexpect.TIMEOUT, pexpect.EOF]


        # refresh the console prompt
        self.pty.sendline()

        for i in range(10):
            rc = self.pty.expect(patterns, timeout=timeout)
            if ex[rc] == "login: ":
                self.pty.sendline(username)
                time.sleep(0.5) # FIXME: what's the point of these waits again?
                continue

            elif ex[rc] == r"[Pp]assword:":
                self.pty.sendline(password)
                time.sleep(0.5)
                continue

            elif ex[rc] in shell_patterns:
                self.shell_setup()
                return

            else:
                # FIXME: For timeout / EOF we might be able to reconnect and retry
                break

        # timeout or some other problem, welp
        log.warning("Problem with the login and/or password prompt,"
                    " raised Exception ConsoleSettings but continuing")
        raise ConsoleSettings(before=pty.before, after=pty.after,
                              msg="Problem with logging in. Probably a "
                                  "connection or credential issue")

    def sudo_bash(self, password, timeout=60):
        ''' A helper that elevates the permissions of the current shell to root by driving sudo'''

        patterns = [".*#",              # 0
                    r"[Pp]assword for", # 1
                    pexpect.TIMEOUT,    # 2
                    pexpect.EOF]        # 3

        self.pty.sendline('sudo -s')
        rc = self.pty.expect(patterns)
        if rc == 2:
            self.pty.sendline(password)
            rc = self.pty.expect(patterns, timeout=timeout)
            if rc == 2:
                raise ValueError("Unable to elevate shell, wrong password?")

        if rc != 0:
            # FIXME: include the expect before / after context
            raise CommandFailed("????")

        # reset the prompt to the one we're expecting on
        set_env_list = self.set_env(self, self.pty)

#    # helper to raise a CommandFailed with the expect context attached
#    def _cmd_failed(self, command, reason):
#        raise CommandFailed(command, )

    def try_command(self, command, timeout=60):
        ''' try to run a command and return the resulting output buffer.

            Note that the output is scraped from the console so you'll get stderr and stdout
            mixed together.

            raises ValueError if you try to run sudo
            raises CommandFailed if the command fails
            might also raise ConsoleDisconnect if the underlying console
            object disconnects'''

        if command.strip().startswith('sudo '):
            raise ValueError('use .sudo_bash() to elevate the shell rather than sudo directly')
        if self.shell_setup_done == False:
            raise RuntimeError('.run_command() can only be used after .setup_term() is called')

        self.pty.sendcontrol('u') # zap anything in the buffer, XXX: how universal is this?
        self.pty.sendline() # refresh the prompt
        self.pty.sendline(command)

        exp = "{}{}".format(self.prompt, command)
        rc = self.pty.expect([exp, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)

        # ok, now grab the output
        rc = self.pty.expect([self.expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)

        # what is this a workaround for? \r\r\n is a very odd sequence
        output_list = self.pty.before.replace("\r\r\n", "\n").splitlines()

        try:
            del output_list[:1]  # remove command from the list
        except Exception as e:
            pass  # EOF or timeout :(

        # check for things going wrong before we get the exit code
        if rc == 1:
            raise CommandFailed(command, "Drive .pty.expect() directly for interactive commands")
        elif rc == 2:
            # original raw buffer if it holds any clues
            output_list, echo_rc = self.try_sendcontrol(self, command)
            raise CommandFailed(command, "run_command timed out after {}s".format(timeout))
        elif rc != 0:
            self.close()
            raise CommandFailed(command, "run_command TIMEOUT or EOF, the command timed out or something,"
                                " probably a connection issue, retry", -1)

        # ok, now grab the status
        self.pty.sendline("echo $?")
        rc = self.pty.expect([self.expect_prompt, pexpect.TIMEOUT, pexpect.EOF],
                              timeout=timeout)
        if rc == 0:
            echo_output = self.pty.before.replace("\r\r\n", "\n").splitlines()
            try:
                echo_rc = int(echo_output[-1])
            except Exception as e:
                log.debug("Error echoing command result. Output: {}".format(echo_output))
                echo_rc = -1
        else:
            raise CommandFailed(command, "run_command echo TIMEOUT, the command may have been ok,"
                                         "but unable to get echo output to confirm result", -1)
        res = output_list
        if echo_rc != 0:
            raise CommandFailed(command, res, echo_rc)

        return res, echo_rc

    def run_command(self, command, timeout=60, retries=0):
        counter = 0
        while counter <= retries:
            try:
                output = self.try_command(command, timeout)
                return output
            except CommandFailed as cf:
                log.debug("CommandFailed cf={}".format(cf))
                if counter == retries:
                    raise cf
                else:
                    counter += 1
                    log.debug("sleeping 2 seconds before retry {:2d} of {:2d}", format(counter, retries))
                    time.sleep(2)

    def run_command_ignore_fail(self, command, timeout=60, retry=0):
        try:
            output = self.run_command(command, timeout, retry)
        except CommandFailed as cf:
            output = cf.output
    
        # XXX: should we try to re-connect here if we lost the console? If the
        # test is ignoring the failure we can probably tolerate losing some
        # output.
        return output

    def get_console(self):
        raise NotImplementedError("get_console is dumb and bad, stop using it")

    def expect(self, patterns, timeout=None):
        # FIXME: we should check if the pty is active or not and raise an
        # exception if it's not. We need to do this here since the console
        # might be backed by something fundementally unreliable like IPMI.
        # As a result, we might need to re-start the pexpect session (or
        # raise an exception).
        return self.pty.expect(patterns, timeout)

class FileConsole(Console):
    def __init__(self, inputfile, logfile=sys.stdout):
        super().__init__(logfile)
        self.pty = opexpect.spawn("cat {}".format(inputfile), logfile=self.logfile)

    def connect(self):
        self.state = ConsoleState.CONNECTED

    def close(self):
        self.state = ConsoleState.DISCONNECTED
        raise RuntimeError("FileConsoles can't be closed")
        self.pty.close()
        self.pty = None


class CmdConsole(Console):
    def __init__(self, cmd, logfile=sys.stdout):
        super().__init__(logfile)
        self.pty = opexpect.spawn(cmd, logfile=self.logfile)

    def connect(self):
        if not self.pty:
            raise Exception("CmdConsoles can't be re-opened")
        self.state = ConsoleState.CONNECTED

    def close(self):
        self.state = ConsoleState.DISCONNECTED
        self.pty.close()
        self.pty = None


class SSHConsole(Console):
    def __init__(self, host, username, password, logfile=sys.stdout, port=22,
                 prompt=None, check_ssh_keys=False, known_hosts_file=None,
                 delaybeforesend=None, use_parent_logger=True):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.check_ssh_keys = check_ssh_keys
        self.known_hosts_file = known_hosts_file
        self.delaybeforesend = delaybeforesend

        # FIXME: clarify what this actually does
        self.use_parent_logger = use_parent_logger

        super().__init__(logfile, prompt)

    def close(self):
        if self.state == ConsoleState.DISCONNECTED:
            raise RuntimeError("Console already closed")
        
        self.state = ConsoleState.DISCONNECTED

#       old code, not really sure it's needed...        
#       self.pty.send("\r")
#       self.pty.send('~.') # really?
#       close_rc = self.pty.expect( [pexpect.TIMEOUT, pexpect.EOF], timeout=10)

        # NB: this can throw exceptions if it can't close the subprocess, but
        # if that happens then something flakey is going on, so let it propagate.
        self.pty.close()
        self.pty = None

    def connect(self, logfile=None):
        if self.state == ConsoleState.CONNECTED:
            raise RuntimeError("Console already connected")

        # FIXME: find a way to probe for afstokenpassing being supported or not
        cmd = ("sshpass -p %s " % (self.password)
               + " ssh"
               + " -p %s" % str(self.port)
               + " -l %s %s" % (self.username, self.host)
               + " -o PubkeyAuthentication=no -o afstokenpassing=no"
               )

        if not self.check_ssh_keys:
            cmd = (cmd
                   + " -q"
                   + " -o 'UserKnownHostsFile=/dev/null' "
                   + " -o 'StrictHostKeyChecking=no'"
                   )
        elif self.known_hosts_file:
            cmd = (cmd + " -o UserKnownHostsFile=" + self.known_hosts_file)

        # For multi threades SSH sessions use individual logger and file handlers per session.
        # FIXME: this should be up to the caller
        if logfile:
            self.log = logger
        elif self.use_parent_logger:
            self.log = log
        else:
            self.log = logger.optest_logger_glob.get_custom_logger(
                __name__)

        log.debug(cmd)

        self.pty = opexpect.spawn(cmd, logfile=self.logfile)


        # FIXME: See qemu.py
        # FIXME: how do we capture stderr? that's where the useful output is...
        time.sleep(1)
        if not self.pty.isalive():
            raise CommandFailed(cmd, self.pty.after, self.pty.exitstatus)

        self.state = ConsoleState.CONNECTED
        # set for bash, otherwise it takes the 24x80 default
        self.pty.setwinsize(1000, 1000)

        if self.delaybeforesend:
            self.pty.delaybeforesend = self.delaybeforesend

        self.pty.logfile_read = logger.FileLikeLogger(self.log)
        # delay here in case messages like afstokenpassing unsupported show up which mess up setup_term
        time.sleep(2)
        log.debug("CONNECT starts Expect Buffer ID={}".format(hex(id(self.pty))))
        return self.pty


