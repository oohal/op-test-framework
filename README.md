## OP-TEST: RELOADED: THE NEXT GENERATION: TAKE TWO: CHEESY SUBTITLE EDITION ##

This repository provides a collection of tools to enable automated testing of
OpenPower system firmware. You can use it for other things too. We're not
going to stop you.

Internally op-test is made up of two components:

1) The optest package which implements a collection of helper logic useful
   for interacting with OpenPower systems.

2) A large test suite for regression and acceptance testing of OpenPower system
   firmware.

The test suite in 2) is implemented using the logic in 1) and uses pytest for
the underlying test running infrastructure.

For full documentation, visit http://open-power.github.io/op-test/

### Requirements ###

op-test should run on any modern Linux based system, and on a few not-so-modern ones.

 - python 3.6 or greater and the corresponding pip
 - A qemu that supports the powernv model (optional)
 - IBM power system functional simulator (Mambo) (optional)
 - ipmitool v1.8.15 or greater
 - sshpass

Network access to the BMC of the system under test. Network access to the host
is not *strictly* required, but the functionality of op-test is greatly limited
without it.

FIXME: Verify these

### Quick Start ###

On Ubuntu:

	apt install python3 python3-pip qemu-utils sshpass
	git clone https://github.com/open-power/op-test

We recommend using a python virtual environment for working with op-test to
avoid conflicts with any python packages provided by the system (or more to
the point, not provided):

	cd op-test/
	python3 -m venv op-test-venv
	source op-test-venv/bin/activate
	pip3 install -r requirements.txt
	pip3 install -e .

This will setup a python venv, install the required packages with pip, and
install the optest library into that virtual envionment so it can be used by
the test suite.

Actually running the test suite is handled through the pytest tool. We need to
provide the details for the system under to test through pytest using a
configuration file:

    cat > qemu_system.conf <<EOF
    [op-test]
    bmc_type=qemu
    qemu_binary=qemu-system-ppc64
    flash_skiboot=test_data/skiboot.lid.nophbs
    flash_kernel=test_data/vmlinux
    flash_initramfs=test_data/petitfs
    EOF

    pytest --config-file ./qemu_system.conf -k boot_to_petitboot

FIXME: validate this

This will cause pytest to run the test verifying that the emulated system
will boot to the petitboot environment. Other useful options for working
with pytest are:

    --collect-only    # only perform test discovery. this gives you a list of all the known tests
    --pdb             # invoke the python debugger when a test fails. Useful for test development
    --lf              # re-run the last failed test
    -k <pattern>      # only run tests that match <pattern>

The full list is available in `pytest --help` and on the documentation on the pytest
website: https://docs.pytest.org/en/latest/usage.html

Additionally, there's some extra command line options to pytest which are specific to op-test:

    --hostlocker    Reserve and request the config from hostlocker (used at ozlabs)
    --aes           Reserve and request the config from AES (used by IBM's firmware team)
    --config-file   As above

Per-user settings, such as AES login details, can be stored in ~/.op-test-framework.conf.

Support for other reservation systems can be added if desired.

##### old stuff I need to look at again starts here #####

### Preparation ###

The target system will need to have a Host OS that can boot.
The Host OS will need to have several things installed on it.

This is a one time setup for the Host OS.  If you reinstall the
Host OS then these steps will need to be completed again to
prepare the Host OS for tests.

### Target System Requirements ###

A basic Linux install is assumed.

You **MUST** have `fwts` installed. To do this:

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:firmware-testing-team/ppa-fwts-stable
    sudo apt-get update
    sudo apt-get install fwts

FWTS for RHEL-like systems will need to clone FWTS and build.

After cloning FWTS see the README for pre-reqs and how-to,
be sure to 'make install' after building to get the proper
paths setup.

git clone git://kernel.ubuntu.com/hwe/fwts.git

It must also have (package names for Debian/Ubuntu systems):

    linux-tools-common linux-tools-generic lm-sensors ipmitool i2c-tools
    pciutils opal-prd opal-utils device-tree-compiler

On RHEL-like systems, package names are:

    lm_sensors ipmitool i2c-tools pciutils kernel-tools dtc

On the Host OS, you will need to clone the skiboot source and then
build the following latest utilities.

    On the Host OS clone the skiboot source:
    git clone https://github.com/open-power/skiboot

    Then:
    cd skiboot/external/xscom-utils
    make
    sudo make install
    cd ../gard
    make
    sudo make install
    cd ../pflash
    make
    sudo make install

### Running the tests ###

    ./op-test -h

Gets you help on what you can run. You will need to (at a minimum) provide
BMC and host login information. For example, to run the default test suite:

    ./op-test --bmc-type AMI             \
              --bmc-ip bmc.example.com   \
              --bmc-username sysadmin    \
              --bmc-password superuser   \
              --bmc-usernameipmi ADMIN   \
              --bmc-passwordipmi admin   \
              --host-ip host.example.com \
              --host-user root           \
              --host-password 1234       \
              --host-lspci host.example.com-lspci.txt

The default test suite will then run.

To get a list of test suites:

    ./op-test --bmc-type AMI --list-suites

You cun run one or more suites by using the `--run-suite` command line option.
For example, you can choose to run tests that are only at the petitboot
command line. By default, the test runner doesn't know what state the machine
is in, so will attempt to turn everything off to get it into a known state.
You can override this initial state with the `--machine-state` parameter.
You can also run individual tests by using the `--run` option.

For example:

      ./op-test --bmc-type AMI                          \
                --bmc-ip bmc.example.com                \
                --bmc-username sysadmin                 \
                --bmc-password superuser                \
                --bmc-usernameipmi ADMIN                \
                --bmc-passwordipmi admin                \
                --host-ip host.example.com              \
                --host-user root                        \
                --host-password 1234                    \
                --host-lspci host.example.com-lspci.txt \
                --machine-state PETITBOOT_SHELL         \
                --run testcases.OpTestPCI.OpTestPCISkiroot

The above will assume the machine is sitting at the petitboot prompt
and will run the OpTestPCISkiroot test.

### Configuration Files ###

You can save arguments to `op-test` in a configuration file.
The `~/.op-test-framework.conf` file is always read, and you can
specify another with `--config-file`.

For example:

    [op-test]
    bmc_type=OpenBMC
    bmc_ip=w39
    bmc_username=root
    bmc_password=0penBmc
    host_ip=w39l
    host_user=ubuntu
    host_password=abc123

### Flashing Firmware ###

In addition to running tests, you can flash firmware before running
the tests. You can also only flash firmware (``--only-flash``).

      ./op-test --bmc-type FSP  ........ \
            --host-img-url http://example.com/images/firenze/b0628b_1726.861/SIGNED/01SV860_103_056.img \
            --flash-skiboot ~/skiboot/skiboot.lid --flash-kernel zImage.epapr \
            --flash-initramfs rootfs.cpio.xz

      ./op-test --bmc-type OpenBMC  ........ \
            --flash-skiboot ~/skiboot/skiboot.lid.xz

Flashing is BMC dependent, so new platforms may not support it.

The ``--host-img-url`` option for FSP systems uses ``update_flash`` from
the petitboot shell to update the firmware image. If additional ``--flash``
options are given, these are flashed *after* the FSP firmware image.
