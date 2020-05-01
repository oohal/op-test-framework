#!/usr/bin/env python3

import optest

# TODO: these are all broken at the momment,  move them into the active
# list as they get ported over to the new system model

#import optest.amiweb
#import optest.bmc      # convert to new system, possibly split SMC and AMI BMCs, rename
#import optest.openbmc  # convert to new system / console, etc
#import optest.mambo    # convert to new system type

#import optest.ipmi     # covert IPMIConsole
#import optest.cronus

#import optest.fsp # system conversion
#import optest.asm
#import optest.hmc

#import optest.installutil

#import optest.thread
#import optest.sol      # we need to re-think how this works
#import optest.util

#import optest.telnet # covert to new Console

import optest.exceptions
import optest.system
import optest.qemu
import optest.opexpect
import optest.petitboot
import optest.console
import optest.config

import optest.constants
import optest.keys     # should get folded into constants


# TODO: figure out how this should be used
import optest.host


# FIXME: we really should rename this something better
import optest.logger

def test_import():
    pass
