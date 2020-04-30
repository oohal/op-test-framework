import time

import pytest

import optest.console as con

# FIXME: this is all pretty crappy, better than nothing i guess

# NB: We need to deal with "real" SSH shell sessions and SSH sessions
# to virtual serial ports. The latter will retain it's state provided
# the shell isn't logged out and that drives the odd behaviour here.

def test_nosetup_raises():
    ssh = con.SSHConsole("ozrom2-bmc", "root", "0penBmc")
    with pytest.raises(RuntimeError):
        ssh.run_command("ls -1")

def test_sudo_raises():
    ssh = con.SSHConsole("ozrom2-bmc", "root", "0penBmc")
    with pytest.raises(ValueError):
        ssh.run_command("sudo ls -1")

def test_ssh_shell():
    ssh = con.SSHConsole("ozrom2-bmc", "root", "0penBmc")

    ssh.connect()
    ssh.shell_setup()
    ssh.run_command("ls -1")
    ssh.close()

    with pyexpect.raises():
        ssh.run_command("ls -1")

    #  In this case it's up to the caller to configure the shell
    ssh.connect()
    ssh.shell_setup()
    ssh.close()

# Hmm, how do we really test the setup behaviour?

def test_ssh_vserial():
    ssh = con.SSHConsole("ozrom2-bmc", "root", "0penBmc", port=2200)

    ssh.connect()
    ssh.shell_setup()
    ssh.run_command("ls -1")

    # before closing grab the pexpect object directly and reset the shell
    ssh.pty.sendline("exit")
    time.sleep(1)
    ssh.pty.sendline("x")
    ssh.close()

    # since it's a virtual serial we expect the prompt to stay setup
    ssh.connect()
    ssh.run_command("ls -1", timeout=2) #
    ssh.close()
