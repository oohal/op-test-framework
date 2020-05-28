#!/usr/bin/env python3

# Example of using the PetitbootHelper.

import os
import time

import optest
import optest.config

from optest.petitboot import PetitbootHelper

optest.logger.log_to_stdout()

sys = optest.config.from_config('./talos2.conf')
sys.get_console().connect()
con = sys.get_console()

boot_option = "DRAGONS BE HERE"

# Power off and boot to petitboot
sys.boot_to('petitboot')

try:
    pb = PetitbootHelper(con)
    pb.goto_menu()
except Exception as e:
    print("Error while driving petitboot. Is the system in petitboot?", e)
    os.exit(1)

for i in range(10):
    options = pb.select_boot_option(boot_option)
    if boot_option in options:
        break

    time.sleep(5)

if boot_option not in options:
    print("timed out looking for dragons")
    os.exit(1)

print("Found the dragons, booting!")
con.pty.sendline('') # cursor is already in place, trigger the boot
