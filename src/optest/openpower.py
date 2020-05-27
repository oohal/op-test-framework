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
        PetitbootState('petitboot', 30, 120),
#        LoginState('login',       login_entry,   30, login_exit,   180),
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
