#!/usr/bin/env python3
#
# This is an example of a script that uses the optest module outside the
# context of pytest.
#
# It assumes that the system is initially at the login prompt and how to
# use the assume_state / resume stuff. To login, run a command, then login
# again.
#
# If we're not at the OS login prompt to start with we'll end up timing out
# since op-test isn't getting the responses it's expecting() for. Point being,
# ensuring the system is in the right state to begin with is the users problem.
#

import optest
import optest.config
import optest.utils

# setup the op-test logger to write to stdout so we can see what's going on.
optest.logger.log_to_stdout()

# Instantiate a optest BaseSystem object from a system config file.
sys = optest.config.from_config('./talos2.conf')
sys.get_console().connect()

# Tell op-test to assume the system is sitting at a login prompt. The state
# name is determined by the system type since the set of states you need to
# traverse is system specific.
#
# e.g. For openpower we go via petitboot while LPARs would boot via grub.
#
sys.assume_state('login')

# Instruct op-test to continue to boot process from the current state (login)
# until we reach the OS shell. Not all states will allow resuming since it's
# not always possible. For eaxmple, you can't resume auto-booting in petitboot
# once it's been cancelled. If the state doesn't support it then it'll throw
# an exception.
sys.boot_resume('os')

# run a command on the host shell via the console:
sys.run_command("echo hi")

# A more long winded form of the above:
sys.get_console().run_command("echo hi!")

# Now exit back to the login prompt.
#
# In this case we grab the raw pty object and use sendline() to execute the
# command. We need to do this because the run_command() helper will try to
# check the exit status of the command it just ran. That'll fail here because
# exit causes the shell to disappear.
#
# Most commands that change the state of the system (e.g. reboot) will break
# in a similar manner. There's not much op-test can do to fix that so it's
# just something you need to be aware of. Op-test tries to provide helpers
# for the common cases, but it can't do everything.
sys.get_console().pty.sendline('exit')

# and... do it again!
sys.assume_state('login')
sys.boot_resume('os')
sys.run_command('echo hi again!')

# exit back so the system is in the same state as when we started.
sys.get_console().pty.sendline('exit')
