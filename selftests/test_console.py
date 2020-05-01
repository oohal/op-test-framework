import time
import pytest
import optest.console as con

@pytest.fixture
def bash():
    yield con.CmdConsole("sh")

def test_nosetup_raises(bash):
    with pytest.raises(RuntimeError):
        bash.run_command("ls -1")

def test_sudo_raises(bash):
    with pytest.raises(ValueError):
        bash.run_command("sudo ls -1")

# FIXME: how do we test the sudo-wrangling in escalate_shell()?

def test_console_basic(bash):
    bash.connect()
    bash.shell_setup()
    bash.run_command("ls -1")
    bash.close()

def test_console_image_cmd(bash):
    bash.connect()

    bash.shell_setup()
    o1 = bash.run_command("ls -1")
    bash.pty.sendline("#ls -1")
    o2 = bash.run_command("ls -1")

    assert o1 == o2

def test_console_resetup(bash):
    bash.connect()

    bash.shell_setup()
    o1 = bash.run_command("ls -1")
    bash.shell_setup()
    o2 = bash.run_command("ls -1")

    assert o1 == o2
    bash.close()

'''
# FIXME: maybe we can use qemu to do this?
@pytest.fixture
def ssh_shell():
    yield con.SSHConsole("ozrom2-bmc", "root", "0penBmc")

def notest_console_ssh_vserial():
    ssh = con.SSHConsole("ozrom2-bmc", "root", "0penBmc", port=2200)

    ssh.connect()
    ssh.shell_setup()
    ssh.run_command("ls -1")

    # before closing grab the pexpect object directly and reset the shell
    ssh.pty.sendline("exit")
    time.sleep(1)
#    ssh.pty.sendline("x")
    ssh.close()

    # since it's a virtual serial we expect the prompt to stay setup
    ssh.connect()
    ssh.run_command("ls -1", timeout=2) #
    ssh.close()
'''
