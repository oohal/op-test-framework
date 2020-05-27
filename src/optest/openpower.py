from .system import BaseSystem, SysState, ConsoleState
from .petitboot import PetitbootState

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

class LoginState(ConsoleState):
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

    def __init__(self, name, enter_timeout, exit_timeout):
        super().__init__(name, self.login_entry, enter_timeout,
                               self.login_exit, exit_timeout) 

    def run(self, system, stop):

        pattern = self._watch_for(system, self.login_entry, self.entry_timeout)

        if stop:
            return

        c = system.get_console()

        # FIXME: Does c.handle_login() do all this for us? '''

        # drive the login prompt if we have to
        if "login" in pattern:
            c.pty.sendline(system.host.username())
            c.expect('assword:')
            c.pty.sendline(system.host.password())

        # wait for a login shell prompt...
        self._watch_for(system, self.login_exit, self.exit_timeout)

    def resume(self, system):
        c = system.get_console()

        # send some blank lines to get us back to the login prompt
        c.pty.sendline('')
        c.pty.sendline('')
        self.run(system, False)


class OsState(SysState):
    ''' this is mainly just here so we can go system.boot_to('os') '''

    def run(self, system, stop):
        system.get_console().shell_setup()

class OpSystem(BaseSystem):
    openpower_state_table = [
        # NB: we're ignoring the SBE since some systems don't have SBE output
        ConsoleState('hostboot',  hb_entry,      30, hb_exit,      180),
        ConsoleState('skiboot',   skiboot_entry, 30, skiboot_exit,  60),
        PetitbootState('petitboot', 30, 120),
    ]

    os_state_table = [
        LoginState('login', 180, 180), # booting can take a while, especially if quiet is on.
        OsState('os', 30, 30)
    ]

    def __init__(self, conf=None, host=None, console=None, pdu=None):
        super().__init__(host=host, console=console, pdu=pdu, conf=conf)

        self._add_state_list(self.openpower_state_table)

        # some lab systems don't have disks and only netboot
        if host.username():
            self._add_state_list(self.os_state_table)

        # a list of error patterns to look for while expect()ing the
        # host console FIXME: these are in OpExpect currently, which is
        # dumb
        self.error_patterns = []
