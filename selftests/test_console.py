import time
import pytest
import optest.console as con

@pytest.fixture
def shell():
    yield con.CmdConsole("sh")

def test_nosetup_raises(shell):
    with pytest.raises(RuntimeError):
        shell.run_command("ls -1")

def test_sudo_raises(shell):
    with pytest.raises(ValueError):
        shell.run_command("sudo ls -1")

# FIXME: how do we test the sudo-wrangling in escalate_shell()?

def test_console_basic(shell):
    shell.connect()
    shell.shell_setup()
    shell.run_command("ls -1")
    shell.close()

def test_console_image_cmd(shell):
    shell.connect()

    shell.shell_setup()
    o1 = shell.run_command("ls -1")
    shell.pty.sendline("#ls -1")
    o2 = shell.run_command("ls -1")

    assert o1 == o2

def test_console_resetup(shell):
    shell.connect()

    shell.shell_setup()
    o1 = shell.run_command("ls -1")
    shell.shell_setup()
    o2 = shell.run_command("ls -1")

    assert o1 == o2
    shell.close()

def test_console_record(shell):
    shell.connect()

    shell.start_capture()
    shell.shell_setup()
    o1 = shell.run_command("ls -1")
    capture = shell.stop_capture()

    assert "HISTFILE" in capture
    print('xxxxxxxxxxxxxxxxxxxxxxx')
    print(capture)
    print('xxxxxxxxxxxxxxxxxxxxxxx')


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
