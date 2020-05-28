#!/usr/bin/env python3

import pexpect
import pyte

from . import logger
from . import console
from .system import ConsoleState, BaseSystem, missed_state, error_pattern
from .keys import OpTestKeys

log = logger.optest_logger_glob.get_logger(__name__)

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

        r = pty.expect(['Petitboot', 'x=exit',
                        "# $", "/ # ", self.c.expect_prompt], timeout=2)

        if r in [0, 1]:
            self.state = self.MENU
        elif r in [2, 3, 4]:
            self.state = self.SHELL
        else:
            raise Exception("Not at petitboot?") # FIXME: subclass it


    def goto_shell(self):
        if self.state == self.SHELL:
            return

        sys_pty = self.c.pty

        for i in range(3):
            sys_pty.send('x')
            pp = self.get_petitboot_prompt()
            if pp == 1:
                self.state = self.SHELL
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
        # send a new line to ensure we're at the prompt
        self.c.pty.sendline('');
        self.c.pty.sendcontrol('d')
        self.c.expect('x=exit')
        self.state = self.MENU
        # FIXME: error checking

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

    def read_screen_updates(self):
        timeout = 2
        buf = ""

        # We should always get some output in response to a key press so we wait
        # a bit until we get a response. Once we've gotten some data back we'll
        # keep reading until we run out of data. That *probably* means it's the
        # end of the screen update.
        #
        # NB: I am almost certain this is going to screw us at some point.
        # We have no way to work out when the entire screen update has landed so
        # we're forced to do this kind of janky crap. Increasing the timeout
        # after the first batch of data is recieved might help, but we wait out
        # that timeout after each petitboot interaction so making it too long
        # can slow things down considerably. It's not too bad on a test system
        # with only a few boot menu options, but the average development system
        # can have dozens of test kernel menu entries.
        #
        # Just in case you're wondering: No, there isn't a simpler way to
        # handle this. Ncurses is quite smart and will try to minimise the
        # re-drawn areas of the screen so unless you're keeping around the
        # full terminal state it's difficult-to-impossible to drive a TUI
        # application reliably.
        #
        # TODO: Make the timeout a config param?
        while True:
            try:
               segment = self.c.pty.read_nonblocking(1024, timeout)
            except pexpect.exceptions.TIMEOUT as e: # Swallow the timeout
                if len(buf):
                    return buf
                else:
                    return None

            buf = buf + segment
            timeout = 0.1

    def select_boot_option(self, target=None):
        '''
        Drives the petitboot ncurses interface to find the target boot menu
        entry. This function only moves the cursor into place, it won't
        actually start the process.

        Returns a list of available boot options. When the target option is
        found we stop looking. If target is None a full list is returned.
        '''
        # NB: The 300,30 are the dimensions that Console::shell_setup() sets.
        # I'm not entirely sure why we use that, but keep them matching.
        screen = pyte.Screen(300, 30)
        input_stream = pyte.Stream(screen)

        self.c.pty.send(OpTestKeys.HOME)
        self.c.pty.sendcontrol('l')
        options = []

        while True:
            # aren't being written to. I'm not too sure how to fix that...
            input_buf = self.read_screen_updates()

            if not input_buf:
                raise Exception("empty buf? that shouldn't happen")
            if len(input_buf) == 1:
                # Saw this a while ago and it can happen as a result of
                # sitting in the shell. If that happens it's because of a
                # bug elsewhere, so don't try to handle it here.
                raise Exception("Bad petitboot state?")

            # Apply the update to our emulated tty
            input_stream.feed(input_buf)

            selected = None
            for l in screen.display:
                # The currently selected item is marked with a ' *'. We skip items
                # with a left bracket as the first character since those are the
                # header lines for boot devices (disk, network, etc).
                if '*' in l[0:3]:
                    log.debug("menu item: ", l.strip())

                if l.startswith(' *') and not l.startswith(' *['):
                    selected = l[2:]
                    break

            if selected:
                # end of the boot option menu?
                selected = selected.strip()
                if "system information" in selected.lower():
                    break

                options.append(selected)
                if target and selected == target:
                    break

            self.c.pty.send(OpTestKeys.DOWN)

        return options

    def boot_menu_option(self, option_name, timeout=60):
        started = time.monotonic()

        while time.monotonic() < start + timeout:
            r = self.select_boot_option(self, option_name)

            if r[-1] == option_name:
                self.c.pty.sendline('') # push button!
                return

        # FIXME: change the type
        raise Exception("Boot option: {} didn't appear inside timeout"
                        .format(option_name, format(timeout)))

    def add_custom_boot_opt(self, kernel, initrd=None, cmdline=None, dtb=None):
        # TODO: implement this. It's possible to add random options using
        # add from URL menu option with file:// URLs. There's probably a way
        # to get pb-event to do it too, but I have to look at the code whenever
        # I try to use pb-event so that's a problem for another day.
        pass

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
        self.boot_option = None

    def run(self, system, exit_at):
        self._watch_for(system, self.pb_entry, self.entry_timeout)


        # NB: Instantiating PetitbootHelper has some side effects which might
        #     cancel auto boot so don't do it in the common path.
        if exit_at:
            pb = PetitbootHelper(system)

            # exit / enter to stop autoboot
            pb.goto_shell()
            pb.goto_menu()
            return

        # TODO: allow choosing a boot option
        if self.boot_option:
            pb = PetitbootHelper(system)
            pb.goto_menu()
            pb.select_boot_option(self.boot_option)
            system.get_console().pty.sendline('') # push button

        # otherwise just wait for the autoboot to happen
        self._watch_for(system, self.pb_exit, self.exit_timeout)
