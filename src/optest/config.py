#!/usr/bin/env python3

import subprocess
import configparser
import traceback
import argparse
import logging
import atexit
import errno
import time
import sys
import os

from datetime import datetime

import optest

import optest.system
import optest.host
from . import utils

from optest.exceptions import HostLocker, AES, ParameterCheck, OpExit
from optest.constants import Constants as BMC_CONST
from .console import SSHConsole
from .openbmc import OpenBMCSystem

from . import logger
log = logger.optest_logger_glob.get_logger(__name__)

# system components
#from optest.hmc import OpTestHMC
#from optest.openbmc import HostManagement
#from optest.amiweb import AMIWeb
#from optest.OpTestUtil import OpTestUtil
#from optest.OpTestCronus import OpTestCronus
from optest.qemu import QemuSystem
#from optest.openbmc import OpenBMCSystem
#from optest.mambo import OpTestMambo
#from optest.bmc import BMCSystem, SMCSystem
import optest.bmc
import optest.ipmi

#from optest.fsp import OpTestFSP
#from optest.openbmc import OpenBMCSystem


# Look at the addons dir for any additional OpTest supported types
# If new type was called Kona, the layout would be as follows
# op-test-framework/addons/Kona/
#                              /OpTestKona.py
#                              /OpTestKonaSystem.py
#                              /OpTestKonaSetup.py
#
# OpTestKona and OpTestKonaSystem follow the same format the other supported type modules
# OpTestKonaSetup is unique for the addons and contains 2 helper functions:
# addBMCType - used to populate the choices list for --bmc-type
# createSystem - does creation of bmc and op_system objects

#import addons # FIXME:

#optAddons = dict()  # Store all addons found.  We'll loop through it a couple time below
# Look at the top level of the addons for any directories and load their Setup modules

qemu_default = "qemu-system-ppc64"
mambo_default = "/opt/ibm/systemsim-p9/run/p9/power9"
mambo_initial_run_script = "skiboot.tcl"
mambo_autorun = "1"
mambo_timeout_factor = 2

default_val = {
    'hostlocker': None,
    'hostlocker_server': 'http://hostlocker.ozlabs.ibm.com',
    'hostlocker_base_url': '/hostlock/api/v1',
    'hostlocker_user': None,
    'hostlocker_locktime': 'never',
    'hostlocker_keep_lock': False,
    'hostlocker_proxy': 'socks5h://localhost:1080',
    'hostlocker_no_proxy_ips': ['10.61.0.0/17', '10.61.128.0/17'],
    'aes': None,
    'aes_server': 'http://fwreport02.rchland.ibm.com',
    'aes_base_url': '/pse_ct_dashboard/aes/rest',
    'aes_user': None,
    'locker_wait': None,
    'aes_add_locktime': 0,
    'aes_rel_on_expire': True,
    'aes_keep_lock': False,
    'aes_proxy': None,
    'aes_no_proxy_ips': None,
    'bmc_type': None,
    'bmc_username': None,
    'bmc_usernameipmi': None,
    'bmc_password': None,
    'bmc_passwordipmi': None,
    'bmc_ip': None,
    'host_user': None,
    'host_password': None,
    'host_ip': None,
}

default_val_fsp = {
    'bmc_type': 'FSP',
    'bmc_username': 'dev',
    'bmc_usernameipmi': 'ADMIN',
    'bmc_password': 'FipSdev',
    'bmc_passwordipmi': 'PASSW0RD',
}

default_val_ami = {
    'bmc_type': 'AMI',
    'bmc_username': 'sysadmin',
    'bmc_usernameipmi': 'ADMIN',
    'bmc_password': 'superuser',
    'bmc_passwordipmi': 'admin',
}

default_val_smc = {
    'bmc_type': 'SMC',
    'bmc_username': 'sysadmin',
    'bmc_usernameipmi': 'ADMIN',
    'bmc_password': 'superuser',
    'bmc_passwordipmi': 'ADMIN',
}

default_val_qemu = {
    'bmc_type': 'qemu',
    # typical KVM Host IP
    # see OpTestQemu.py
    'host_ip': '10.0.2.15',
    # typical VM skiroot IP
    # see OpTestQemu.py
}

default_val_mambo = {
    'bmc_type': 'mambo',
}

default_templates = {
    # lower case insensitive lookup used later
    'openbmc': default_val,
    'fsp': default_val_fsp,
    'ami': default_val_ami,
    'smc': default_val_smc,
    'qemu': default_val_qemu,
    'mambo': default_val_mambo,
}


# FIXME: none of this is really used any more since pytest handles parsing arguments.
# we're keeping it here mainly because it's used to populate the default values of
# the config object (see below).
#
# we could port over all these command line options so that they're pytest command
# line options, but eh... pytest already has a million command line options which
# makes the --help is borderline unreadable as-is. Adding all the options from
# op-test is just going to make things worse.
#
# IMO: a) only have --aes, --config-file, and --hostlocker as command line params
# everything else comes from the config files. Maybe we can add a --optest-config
# command line option that allows specific settings to be override from the command
# line.
#
# we also need to work out where the documentation of these should go since currently
# that's provided by --help. Docstrings for the individual system classes might help,
# but we'd like to have a complete list somewhere.
#

def get_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-c", "--config-file", help="Configuration File",
                        metavar="FILE")

    # Options to set the output directory and suffix on the output
    parser.add_argument(
        "-o", "--output", help="Output directory for test reports.  Can also be set via OP_TEST_OUTPUT env variable.")
    parser.add_argument(
        "-l", "--logdir", help="Output directory for log files.  Can also be set via OP_TEST_LOGDIR env variable.")
    parser.add_argument(
        "--suffix", help="Suffix to add to all reports.  Default is current time.")

    lockgroup = parser.add_mutually_exclusive_group()
    lockgroup.add_argument("--hostlocker", metavar="HOST_NAME",
                           help="Hostlocker host name to checkout, see HOSTLOCKER GROUP below for more options")
    lockgroup.add_argument("--aes", nargs='+', metavar="ENV_NAME|Q|L|U",
                           help="AES environment name to checkout or Q|L|U for query|lock|unlock of AES environment, refine by adding --aes-search-args, see AES GROUP below for more options")

    hostlockergroup = parser.add_argument_group('HOSTLOCKER GROUP',
                                                'Options for HostLocker (see above optional arguments --hostlocker, mutually exclusive with --aes)')
    hostlockergroup.add_argument(
        "--hostlocker-user", help="UID login for HostLocker, uses OS UID if not specified, you must have logged in at least once via the web prior to running")
    hostlockergroup.add_argument(
        "--hostlocker-server", help="Override URL for HostLocker Server")
    hostlockergroup.add_argument(
        "--hostlocker-base-url", help="Override Base URL for HostLocker")
    hostlockergroup.add_argument(
        "--hostlocker-locktime", help="Time duration (see web for formats) to lock the host, never is the default, it will unlock post test")
    hostlockergroup.add_argument("--hostlocker-keep-lock", default=False,
                                 help="Release the lock once the test finishes, defaults to False to always release the lock post test")
    hostlockergroup.add_argument(
        "--hostlocker-proxy", help="socks5 proxy server setup, defaults to use localhost port 1080, you must have the SSH tunnel open during tests")
    hostlockergroup.add_argument(
        "--hostlocker-no-proxy-ips", help="Allows dynamic determination if you are on proxy network then no proxy will be used")

    aesgroup = parser.add_argument_group('AES GROUP',
                                         'Options for AES (see above optional arguments --aes, mutually exclusive with --hostlocker)')
    aesgroup.add_argument("--aes-search-args", nargs='+', help='AES allowable, match done by regex '
                          + 'like --aes-search-args Environment_Name=wl2, run --aes Q for more info')
    aesgroup.add_argument(
        "--aes-user", help="UID login for AES, uses OS UID if not specified, you must have logged in at least once via the web prior to running")
    aesgroup.add_argument("--aes-server", help="Override URL for AES Server")
    aesgroup.add_argument("--aes-base-url", help="Override Base URL for AES")
    aesgroup.add_argument("--aes-rel-on-expire", default=True,
                          help="AES setting related to aes-add-locktime when making the initial reservation, defaults to True, does not affect already existing reservations")
    aesgroup.add_argument("--aes-keep-lock", default=False,
                          help="Release the AES reservation once the test finishes, defaults to False to always release the reservation post test")
    aesgroup.add_argument("--locker-wait", type=int, default=0,
                          help="Time in minutes to try for the lock, default does not retry")
    aesgroup.add_argument("--aes-add-locktime", default=0, help="Time in hours (float value) of how long to reserve the environment, reservation defaults to never expire but will release the environment post test, if a reservation already exists for UID then extra time will be attempted to be added, this does NOT work on NEVER expiring reservations, be sure to add --aes-keep-lock or else the reservation will be given up after the test, use --aes L option to manage directly and --aes U option to manage directly without running a test")
    aesgroup.add_argument(
        "--aes-proxy", help="socks5 proxy server setup, defaults to use localhost port 1080, you must have the SSH tunnel open during tests")
    aesgroup.add_argument(
        "--aes-no-proxy-ips", help="Allows dynamic determination if you are on proxy network then no proxy will be used")

    bmcgroup = parser.add_argument_group('BMC',
                                         'Options for Service Processor')
    # The default supported BMC choices in --bmc-type
    bmcChoices = ['AMI', 'SMC', 'FSP', 'FSP_PHYP', 'OpenBMC', 'qemu', 'mambo']
    # Loop through any addons let it append the extra bmcChoices
#    for opt in optAddons:
#        bmcChoices = optAddons[opt].addBMCType(bmcChoices)
    bmcgroup.add_argument("--bmc-type",
                          choices=bmcChoices,
                          help="Type of service processor")
    bmcgroup.add_argument("--bmc-ip", help="BMC address")
    bmcgroup.add_argument("--bmc-mac", help="BMC MAC address")
    bmcgroup.add_argument("--bmc-username", help="SSH username for BMC")
    bmcgroup.add_argument("--bmc-password", help="SSH password for BMC")
    bmcgroup.add_argument("--bmc-usernameipmi", help="IPMI username for BMC")
    bmcgroup.add_argument("--bmc-passwordipmi", help="IPMI password for BMC")
    bmcgroup.add_argument("--bmc-prompt", default="#",
                          help="Prompt for BMC ssh session")
    bmcgroup.add_argument("--smc-presshipmicmd")
    bmcgroup.add_argument("--qemu-binary", default=qemu_default,
                          help="[QEMU Only] qemu simulator binary")
    bmcgroup.add_argument("--mambo-binary", default=mambo_default,
                          help="[Mambo Only] mambo simulator binary, defaults to /opt/ibm/systemsim-p9/run/p9/power9")
    bmcgroup.add_argument("--mambo-initial-run-script", default=mambo_initial_run_script,
                          help="[Mambo Only] mambo simulator initial run script, defaults to skiboot.tcl")
    bmcgroup.add_argument("--mambo-autorun", default=mambo_autorun,
                          help="[Mambo Only] mambo autorun, defaults to '1' to autorun")
    bmcgroup.add_argument("--mambo-timeout-factor", default=mambo_timeout_factor,
                          help="[Mambo Only] factor to multiply all timeouts by, defaults to 2")

    hostgroup = parser.add_argument_group('Host', 'Installed OS information')
    hostgroup.add_argument("--host-ip", help="Host address")
    hostgroup.add_argument("--host-user", help="SSH username for Host")
    hostgroup.add_argument("--host-password", help="SSH password for Host")
    hostgroup.add_argument("--host-serial-console-command",
                           help="Command to get serial console for host."
                           "Used instead of IPMI SoL. Useful for buggy BMCs.")

    hostgroup.add_argument("--host-lspci", help="Known 'lspci -n -m' for host")
    hostgroup.add_argument("--host-scratch-disk",
                           help="A block device we can erase", default="")
    hostgroup.add_argument("--qemu-scratch-disk",
                           help="A block device for qemu", default=None)
    hostgroup.add_argument("--host-prompt", default="#",
                           help="Prompt for Host SSH session")

    hostinstgroup = parser.add_argument_group(
        'Host OS Install', 'Options for installing an OS on the Host')
    hostinstgroup.add_argument(
        "--host-name", help="Host name", default="localhost")
    hostinstgroup.add_argument(
        "--host-gateway", help="Host Gateway", default="")
    hostinstgroup.add_argument(
        "--host-submask", help="Host Subnet Mask", default="255.255.255.0")
    hostinstgroup.add_argument("--host-mac",
                               help="Host Mac address (used by OS installer to set up OS on the host)",
                               default="")
    hostinstgroup.add_argument("--host-dns",
                               help="Host DNS Servers (used by OS installer to set up OS on the host)",
                               default="")
    hostinstgroup.add_argument("--proxy", default="", help="proxy for the Host to access the internet. "
                               "Only needed for tests that install an OS")

    hostcmdgroup = parser.add_argument_group(
        'Host Run Commands', 'Options for Running custom commands on the Host')
    hostcmdgroup.add_argument("--host-cmd", help="Command to run", default="")
    hostcmdgroup.add_argument(
        "--host-cmd-file", help="Commands to run from file", default="")
    hostcmdgroup.add_argument(
        "--host-cmd-timeout", help="Timeout for command", type=int, default=1000)
    hostcmdgroup.add_argument("--host-cmd-resultpath",
                              help="Result path from host", default="")

    hostgroup.add_argument("--platform",
                           help="Platform (used for EnergyScale tests)",
                           choices=['unknown', 'habanero', 'firestone', 'garrison', 'firenze', 'p9dsu', 'witherspoon', 'mihawk'])

    osgroup = parser.add_argument_group(
        'OS Images', 'OS Images to boot/install')
    osgroup.add_argument(
        "--os-cdrom", help="OS CD/DVD install image", default=None)
    osgroup.add_argument("--os-repo", help="OS repo", default="")
    osgroup.add_argument("--no-os-reinstall",
                         help="If set, don't run OS Install test",
                         action='store_true', default=False)

    gitgroup = parser.add_argument_group(
        'git repo', 'Git repository details for upstream kernel install/boot')
    gitgroup.add_argument(
        "--git-repo", help="Kernel git repository", default=None)
    gitgroup.add_argument("--git-repoconfigpath",
                          help="Kernel config file to be used", default=None)
    gitgroup.add_argument(
        "--git-repoconfig", help="Kernel config to be used", default="ppc64le_defconfig")
    gitgroup.add_argument(
        "--git-branch", help="git branch to be used", default="master")
    gitgroup.add_argument(
        "--git-home", help="home path for git repository", default="/home/ci")
    gitgroup.add_argument(
        "--git-patch", help="patch to be applied on top of the git repository", default=None)
    gitgroup.add_argument(
        "--use-kexec", help="Use kexec to boot to new kernel", action='store_true', default=False)
    gitgroup.add_argument("--append-kernel-cmdline",
                          help="Append kernel commandline while booting with kexec", default=None)

    imagegroup = parser.add_argument_group(
        'Images', 'Firmware LIDs/images to flash')
    imagegroup.add_argument(
        "--bmc-image", help="BMC image to flash(*.tar in OpenBMC, *.bin in SMC)")
    imagegroup.add_argument("--host-pnor", help="PNOR image to flash")
    imagegroup.add_argument("--host-hpm", help="HPM image to flash")
    imagegroup.add_argument(
        "--host-img-url", help="URL to Host Firmware image to flash on FSP systems (Must be URL accessible petitboot shell on the host)")
    imagegroup.add_argument("--flash-skiboot",
                            help="skiboot to use/flash. Depending on platform, may need to be xz compressed")
    imagegroup.add_argument("--flash-kernel",
                            help="petitboot zImage.epapr to use/flash.")
    imagegroup.add_argument("--flash-initramfs",
                            help="petitboot rootfs to use/flash. Not all platforms support this option")
    imagegroup.add_argument("--flash-part", nargs=2, metavar=("PART name", "bin file"), action='append',
                            help="PNOR partition to flash, Ex: --flash-part OCC occ.bin")
    imagegroup.add_argument("--noflash", "--no-flash", action='store_true', default=False,
                            help="Even if images are specified, don't flash them")
    imagegroup.add_argument("--only-flash", action='store_true', default=False,
                            help="Only flash, don't run any tests (even if specified)")
    imagegroup.add_argument("--pflash",
                            help="pflash to copy to BMC (if needed)")
    imagegroup.add_argument("--pupdate",
                            help="pupdate to flash PNOR for Supermicro systems")
#    imagegroup.add_argument("--pdbg",
#                           help="pdbg binary to be executed on BMC")

    stbgroup = parser.add_argument_group(
        'STB', 'Secure and Trusted boot parameters')
    stbgroup.add_argument("--un-signed-pnor",
                          help="Unsigned or improperly signed PNOR")
    stbgroup.add_argument(
        "--signed-pnor", help="Properly signed PNOR image(imprint)")
    stbgroup.add_argument(
        "--signed-to-pnor", help="Properly signed PNOR image(imprint or production)")
    stbgroup.add_argument("--key-transition-pnor",
                          help="Key transition PNOR image")
    stbgroup.add_argument("--test-container", nargs=2, metavar=("PART name", "bin file"), action='append',
                          help="PNOR partition container to flash, Ex: --test-container CAPP capp_unsigned.bin")
    stbgroup.add_argument("--secure-mode", action='store_true',
                          default=False, help="Secureboot mode")
    stbgroup.add_argument("--trusted-mode", action='store_true',
                          default=False, help="Trustedboot mode")
    kernelcmdgroup = parser.add_argument_group("Kernel cmdline options",
                                               "add/remove kernel commandline arguments")
    kernelcmdgroup.add_argument("--add-kernel-args",
                                help="Kernel commandline option to be added",
                                default="")
    kernelcmdgroup.add_argument("--remove-kernel-args",
                                help="Kernel commandline option to be removed",
                                default="")
    cronusgroup = parser.add_argument_group("Cronus", "Cronus Config options")
    cronusgroup.add_argument(
        "--cronus-release", default="auto", help="Cronus Release")
    cronusgroup.add_argument(
        "--cronus-product", default="p9", help="Cronus Product")
    cronusgroup.add_argument("--cronus-system-type",
                             default="witherspoon", help="Cronus System Type")
    cronusgroup.add_argument("--cronus-code-level",
                             default="dev", help="Cronus Code Level")
#    cronusgroup.add_argument("--cronus-hdct", default="/opt/openpower/p9/crondump/HDCT_P9", help="Cronus Hardware Dump Content Table file")
    cronusgroup.add_argument("--cronus-hdct", default="HDCT.txt",
                             help="Cronus Hardware Dump Content Table file")
    cronusgroup.add_argument("--cronus-dump-directory",
                             default=None, help="Cronus dump file directory")
    cronusgroup.add_argument("--cronus-dump-suffix",
                             default="optest", help="Cronus dump file suffix")
    cronusgroup.add_argument("--cronus-smart-path", action='store_true',
                             default=False, help="Cronus path added after /usr/bin")
    hmcgroup = parser.add_argument_group('HMC',
                                         'HMC CLI commands')
    hmcgroup.add_argument("--hmc-ip", help="HMC address")
    hmcgroup.add_argument("--hmc-username", help="SSH username for HMC")
    hmcgroup.add_argument("--hmc-password", help="SSH password for HMC")
    hmcgroup.add_argument(
        "--system-name", help="Managed system/server name in HMC", default=None)
    hmcgroup.add_argument(
        "--lpar-name", help="Lpar name as provided in HMC", default=None)
    hmcgroup.add_argument(
        "--lpar-prof", help="Lpar profile provided in HMC", default=None)
    hmcgroup.add_argument(
        "--lpar-vios", help="Lpar VIOS to boot before other LPARS", default=None)

    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument("--check-ssh-keys", action='store_true', default=False,
                            help="Check remote host keys when using SSH (auto-yes on new)")
    misc_group.add_argument("--known-hosts-file",
                            help="Specify a custom known_hosts file")
    misc_group.add_argument("--accept-unknown-args", default=False, action='store_true',
                            help="Don't exit if we find unknown command line arguments")

    return parser


class OpTestConfiguration():
    def __init__(self, **kwargs):
        self.args = {}

        # dumb hack to get the default values until we get rid of the stuff above
        parser = get_parser()
        self.defaults = vars(parser.parse_args(""))
        self.args.update(self.defaults)

        # first, parse the per-user config stuff
        user_file = kwargs.get('user_config', "~/.op-test-framework.conf")
        if user_file and not kwargs.get('skip_user_conf'):
            user_file = os.path.expanduser(user_file)
            self.user_conf = self.parse_config_file(user_file, True)
            self.args.update(self.user_conf)

        # second, check for host reservation systems and grab any config data
        # NB: We don't make any reservations here
        if kwargs.get('hostlocker'):
            raise Exception('FIXME: implement hostlocker support')
        elif kwargs.get('aes'):
            raise Exception('FIXME: implement aes support')

        # now take the args from the local config file (if there is one)
        # we do this after checking the lockers so that you can override the
        # args they provide with your own in the local config.
        config_file = kwargs.get('config')
        if config_file:
            self.local_cfg = self.parse_config_file(config_file)
            self.args.update(self.local_cfg)

        # now fold in the overrides
        overrides = kwargs.get('overrides')
        if overrides:
            self.args.update(overrides)

        # peliminary validation
        if not self.args.get('bmc_type'):
            raise KeyError("A bmc_type must be set")

        if self.args.get('known_hosts_file') and \
           not self.args.get('check_ssh_keys'):
            raise Exception("known-hosts-file requires check-ssh-keys")

        self.dump = True  # Need state for cleanup
        self.lock_dict = {'res_id': None,
                          'name': None,
                          'Group_Name': None,
                          'envs': [],
                          }

    def parse_config_file(self, filename, optional=False):
        config = configparser.ConfigParser()

        if not os.access(filename, os.R_OK):
            if optional:
                return {}
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), filename)

        config.read(filename)

        if config.has_section('op-test'):
            d = dict(config.items('op-test'))
        else:
            msg = "{} is missing an an [op-test] section header".format(filename)
            raise configparser.NoSectionError(msg)

        # FIXME: maybe we should allow config sections for specific tests?
        return dict(config.items('op-test'))

    def unlock(self):
        # FIXME: move the aes/hostlocker wrangling into here
        if False:
            self.cleanup()

    def cleanup(self):
        self.unlock()

    # How much of this should be done here? might be better off in the test
    # harness, but then again it might be useful to someone as a part of
    # the library
    def lock(self, wait_time=None):
        if not wait_time:
            wait_time = self.args.get(locker_wait, 60) # in minutes

        # setup AES and Hostlocker configs after the logging is setup
        locker_timeout = time.time() + 60 * wait_time
        locker_code = errno.ETIME  # 62
        locker_message = ("OpTestSystem waited {} minutes but was unable"
                          " to lock environment/host requested,"
                          " either pick another environment/host or increase "
                          "--locker-wait, try --aes q with options for "
                          "--aes-search-args to view availability, or as"
                          " appropriate for your hostlocker"
                          .format(wait_time))
        locker_exit_exception = OpExit(message=locker_message,
                                       code=locker_code)
        while True:
            try:
                rollup_flag = False
                self.util.check_lockers()
                break
            except Exception as e:
                OpTestLogger.optest_logger_glob.optest_logger.debug(
                    "locker_wait Exception={}".format(e))
                if "unable to lock" in e.message:
                    self.aes_print_helpers = False
                    # SystemExit exception needs message to print
                    rollup_message = locker_exit_exception.message
                    rollup_exception = locker_exit_exception
                else:
                    rollup_message = e.message
                    rollup_exception = e
                    rollup_flag = True  # bubble exception out
                if time.time() > locker_timeout or rollup_flag:
                    # if not "unable to lock" we bubble up underlying exception
                    OpTestLogger.optest_logger_glob.optest_logger.warning(
                        "{}".format(rollup_message))
                    raise rollup_exception
                else:
                    OpTestLogger.optest_logger_glob.optest_logger.info(
                        "OpTestSystem waiting for requested environment/host"
                        " total time to wait is {} minutes, we will check"
                        " every minute"
                        .format(wait_time))
                    time.sleep(60)

    # FIXME: Ported over from the old op-test. Look at cracking it into
    #        something more sensible. A per-system @staticmethod that takes
    #        a config object and returns a system might make sense. Or we could
    #        fold it into the constructor.
    def create_system(self):
        '''instantiates the correct system objected based on this config'''

        # before we get carried away verify that we can at least ping the bmc
        if self.args['bmc_ip']:
            try:
                utils.ping(self.args['bmc_ip'], totalSleepTime=5)
            except Exception as e:
                log.info("Unable to ping the BMC at {}".format(self.args['bmc_ip']))
                raise e # FIXME: throw a new one? use a different exception type?

        # grab our serial console if we've got one...
        console_cmd = self.args['host_serial_console_command']
        if console_cmd:
            console = optest.console.CmdConsole(console_cmd)
        else:
            console = None

        # FIXME: implement pdu support
        pdu = None

        # TODO: have a think about what the host object actually represents,
        #       and how it's different to the system object. It's a bit awkward
        #       right now...
        host = optest.host.OpTestHost(None, # results dir, whatever that is
                                            self.args['host_ip'],
                                            self.args['host_user'],
                                            self.args['host_password'],
                                            self.args['bmc_ip'],
#                                            self.output,
                                            scratch_disk=self.args['host_scratch_disk'],
                                            proxy=self.args['proxy'],
#                                            logfile=self.logfile,
                                            check_ssh_keys=self.args['check_ssh_keys'],
                                            known_hosts_file=self.args['known_hosts_file'])

        if self.args['bmc_type'] in ['AMI', 'SMC']:
            bmc = None
            if self.args['bmc_type'] in ['AMI']:
                '''
                # FIXME: ipmi and web should probably be instantiated in the
                # BMC object's constructor
                web = OpTestWeb(self.args['bmc_ip'],
                                self.args['bmc_usernameipmi'],
                                self.args['bmc_passwordipmi'])

                ipmi = OpTestIPMI(self.args['bmc_ip'],
                                  self.args['bmc_usernameipmi'],
                                  self.args['bmc_passwordipmi'],
                                  host=host,
                                  host_console_command=self.args['host_serial_console_command'],
                                  logfile=self.logfile,
                                  )

                bmc = OpTestBMC(ip=self.args['bmc_ip'],
                                username=self.args['bmc_username'],
                                password=self.args['bmc_password'],
                                logfile=self.logfile,
                                ipmi=ipmi,
                                web=web,
                                check_ssh_keys=self.args['check_ssh_keys'],
                                known_hosts_file=self.args['known_hosts_file']
                                )
                '''
                raise "FIXME: support AMI"
            elif self.args['bmc_type'] in ['SMC']:
                ipmi = optest.ipmi.OpTestSMCIPMI(self.args['bmc_ip'],
                                     self.args['bmc_usernameipmi'],
                                     self.args['bmc_passwordipmi'],
#                                     logfile=self.logfile,
#                                     host=host,
                                     )
                bmc = optest.bmc.OpTestSMC(ip=self.args['bmc_ip'],
                                username=self.args['bmc_username'],
                                password=self.args['bmc_password'],
                                ipmi=ipmi,
                                check_ssh_keys=self.args['check_ssh_keys'],
                                known_hosts_file=self.args['known_hosts_file']
                                )
            self.op_system = optest.bmc.IPMISystem(
                host=host,
                ipmi=ipmi,
                bmc=bmc,
                console=console,
                pdu=pdu,
            )
        elif self.args['bmc_type'] in ['FSP']:
            raise "FIXME: support FSP"
            '''
            ipmi = OpTestIPMI(self.args['bmc_ip'],
                              None,  # FSP does not use UID
                              self.args['bmc_passwordipmi'],
                              host=host,
                              logfile=self.logfile)
            bmc = OpTestFSP(self.args['bmc_ip'],
                            self.args['bmc_username'],
                            self.args['bmc_password'],
                            ipmi=ipmi,
                            )
            self.op_system = optest.OpTestFSP.OpTestFSPSystem(
                state=self.startState,
                bmc=bmc,
                host=host,
                conf=self,
            )
            ipmi.set_system(self.op_system)
            '''
        elif self.args['bmc_type'] in ['FSP_PHYP']:
            raise "FIXME: support FSP_PHYP"
            '''
            host = optest.OpTestHost.OpTestLPAR(self.args['host_ip'],
                                            self.args['host_user'],
                                            self.args['host_password'],
                                            self.args['bmc_ip'],
                                            self.output,
                                            scratch_disk=self.args['host_scratch_disk'],
                                            proxy=self.args['proxy'],
                                            logfile=self.logfile,
                                            check_ssh_keys=self.args['check_ssh_keys'],
                                            known_hosts_file=self.args['known_hosts_file'],
                                            conf=self)
            hmc = None
            if all(v is not None for v in [self.args['hmc_ip'], self.args['hmc_username'], self.args['hmc_password'],
                                           self.args['system_name'], self.args['lpar_name']]):
                hmc = OpTestHMC(self.args['hmc_ip'],
                                self.args['hmc_username'],
                                self.args['hmc_password'],
                                managed_system=self.args['system_name'],
                                lpar_name=self.args['lpar_name'],
                                lpar_vios=self.args['lpar_vios'],
                                lpar_prof=self.args['lpar_prof'],
                                lpar_user=self.args['host_user'],
                                lpar_password=self.args['host_password'],
                                logfile=self.logfile
                                )
            else: # FIXME: param validation should be done in the system constructor
                raise Exception("HMC IP, username and password is required")
            bmc = OpTestFSP(self.args['bmc_ip'],
                            self.args['bmc_username'],
                            self.args['bmc_password'],
                            hmc=hmc,
                            )
            self.op_system = optest.OpTestHMC.OpTestLPARSystem(
                state=self.startState,
                bmc=bmc,
                host=host,
                conf=self,
            )
            hmc.set_system(self.op_system)
            '''
        elif self.args['bmc_type'] in ['OpenBMC']:
            # FIXME: should this be moved into the OpenBMCSystem constructor?
            if not console:
                console = SSHConsole(self.args['bmc_ip'],
                                     self.args['bmc_username'],
                                     self.args['bmc_password'],
#                                     self.logfile,
                                     port=2200,
                                     check_ssh_keys=self.args['check_ssh_keys'],
                                     known_hosts_file=self.args['known_hosts_file'])

            self.op_system = OpenBMCSystem(
                        host=host,
                        console=console,
                        hostname=self.args['bmc_ip'],
                        username=self.args['bmc_username'],
                        password=self.args['bmc_password'],
#                        logfile=self.logfile,
                        check_ssh_keys=self.args['check_ssh_keys'],
                        known_hosts_file=self.args['known_hosts_file'],
            )
        elif self.args['bmc_type'] in ['qemu']:
            if console:
                raise Exception("qemu can't use a seperate console (yet)")
            sys = QemuSystem(conf=self,
                             qemu_binary=self.args['qemu_binary'],
                             pnor=self.args['host_pnor'],
                             skiboot=self.args['flash_skiboot'],
                             kernel=self.args['flash_kernel'],
                             initramfs=self.args['flash_initramfs'],
                             cdrom=self.args['os_cdrom'],
#                             logfile=self.logfile,
                             host=host)
            self.op_system = sys
        elif self.args['bmc_type'] in ['mambo']:
            raise "FIXME: support mambo"
            '''
            # FIXME: this stuff should be verified in the mambo constructor
            if not (os.stat(self.args['mambo_binary']).st_mode & stat.S_IXOTH):
                raise ParameterCheck(message="Check that the file exists with X permissions mambo-binary={}"
                                     .format(self.args['mambo_binary']))
            if self.args['flash_skiboot'] is None \
                    or not os.access(self.args['flash_skiboot'], os.R_OK):
                raise ParameterCheck(message="Check that the file exists with R permissions flash-skiboot={}"
                                     .format(self.args['flash_skiboot']))
            if self.args['flash_kernel'] is None \
                    or not os.access(self.args['flash_kernel'], os.R_OK):
                raise ParameterCheck(message="Check that the file exists with R permissions flash-kernel={}"
                                     .format(self.args['flash_kernel']))
            bmc = OpTestMambo(mambo_binary=self.args['mambo_binary'],
                              mambo_initial_run_script=self.args['mambo_initial_run_script'],
                              mambo_autorun=self.args['mambo_autorun'],
                              skiboot=self.args['flash_skiboot'],
                              kernel=self.args['flash_kernel'],
                              initramfs=self.args['flash_initramfs'],
                              timeout_factor=self.args['mambo_timeout_factor'],
                              logfile=self.logfile)
            self.op_system = optest.OpTestMambo.OpTestMamboSystem(host=host,
                                                                   bmc=bmc,
                                                                   state=self.startState,
                                                                   conf=self,
                                                                   )
            bmc.set_system(self.op_system)
            '''

        # FIXME: address the addon stuff when we move this out of here.
        # Check that the bmc_type exists in our loaded addons then create our objects
#        elif self.args['bmc_type'] in optAddons:
#            # FIXME: hmm, how do we support this sort of thing?
#            (bmc, self.op_system) = optAddons[self.args['bmc_type']].createSystem(
#                self, host)
        else:
            self.util.cleanup()
            raise Exception("Unsupported BMC Type '{}', check your "
                            "upper/lower cases for bmc_type and verify "
                            "any credentials used from HostLocker or "
                            "AES Version (see aes_get_creds "
                            "version_mappings)".format(self.args['bmc_type']))

        # FIXME: All the cronus stuff is probably broken. Fix it up at some point.
        # FIXME: We should add a cronus / BML system type.
#        if self.args['cronus_product']:
#            self.cronus = OpTestCronus(self.conf)

        print("created objects")
        return self.op_system

    def bmc(self):
        raise Exception('fix this test')
    def hmc(self):
        raise Exception('fix this test')
    def system(self):
        raise Exception('fix this test')
    def host(self):
        raise Exception('fix this test')
    def ipmi(self):
        raise Exception('fix this test')
    def platform(self):
        raise Exception('fix this test')

    def lspci_file(self): # XXX: maybe this one is justified?
        raise Exception('fix this test')
