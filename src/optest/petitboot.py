#!/usr/bin/env python3

import pexpect

from . import logger
from . import console
from .system import ConsoleState, BaseSystem, missed_state, error_pattern

log = logger.optest_logger_glob.get_logger(__name__)

# FIXME: port to the new framework

class PetitbootHelper():
    ''' helper class for driving petitboot '''

    MENU = 0
    SHELL = 1

    def __init__(self, input_console):
        if isinstance(input_console, BaseSystem):
            self.c = input_console.get_console()
        elif isinstance(input_console, console.Console):
            self.c = input_console
        else:
            raise TypeError("Unknown console object?")

        pty = self.c.pty

        pty.zap()

        # NB: ctrl+l only refreshes on newer petitboot versions, might need to
        # do something to support older ones.
        pty.sendcontrol('l')
        r = pty.expect(['Petitboot', 'exit=x', "# $", pexpect.TIMEOUT, pexpect.EOF], timeout=2)

        if r in [0, 1]:
            self.state = self.MENU
        elif r == 2:
            self.state = self.SHELL
        else:
            raise Exception("not at petitboot") # FIXME: subclass it


    def goto_shell(self):
        if self.state == self.SHELL:
            return

        sys_pty = self.c.pty

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
    def goto_menu(self):
        if self.state == self.MENU:
            return

        sys_pty = self.c.pty

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
        sys_pty = self.c.pty
        log.debug("USING GPP Expect Buffer ID={}".format(hex(id(sys_pty))))
        sys_pty.sendline()
        pes_rc = sys_pty.expect(
            [".*#", ".*# $", pexpect.TIMEOUT, pexpect.EOF], timeout=1)

        if pes_rc in [0, 1]:
            self.c.shell_setup()
            my_pp = 1
        return my_pp

    def to_menu(self):
        sys_pty = self.c.pty
        log.debug("USING EPS 1 Expect Buffer ID={}".format(hex(id(sys_pty))))
        eps_rc = self.try_exit(sys_pty)
        if eps_rc == 0:  # Petitboot
            return
        else:  # we timed out or eof
            try:
                self.util.try_recover(self.console, counter=3)
                # if we get back here we're good and at the prompt
                # but we lost our sys_pty, so get a new one
                sys_pty = self.c
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
        raw_pty = self.c.pty
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



    # FIXME: moved this in from somwehere, need to make it work

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


class PetitbootState(ConsoleState):
    pb_entry = {
        'Petitboot': None,
        'x=exit': None,
        '/ #': None,
        'login: ': missed_state,
        'Aborting!': error_pattern,
    }

    pb_exit = {
        "Performing kexec reboot" : None ,
        "SIGTERM received, booting..." : None,
        "kexec_core: Starting new kernel" : None,
        'login: ': None,
        '/ #': error_pattern,
        'mon> ': error_pattern,
    #    'dracut:/#': dracut_callback,
    }

    def __init__(self, name, enter_timeout, exit_timeout):
        super().__init__(name, PetitbootState.pb_entry, enter_timeout,
                               PetitbootState.pb_exit, exit_timeout)

    def run(self, system, exit_at):
        self._watch_for(system, self.pb_entry, self.entry_timeout)

        if exit_at:
            pb = PetitbootHelper(system)

            # exit / enter to stop autoboot
            pb.goto_shell()
            pb.goto_menu()
            return

        # TODO: allow choosing a boot option

        # otherwise just wait for the autoboot to happen
        self._watch_for(system, self.pb_exit, self.exit_timeout)
