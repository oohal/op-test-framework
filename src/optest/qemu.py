#!/usr/bin/env python3
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2015,2017
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
Support testing against Qemu simulator
"""

import sys
import time
import pexpect
import subprocess
import tempfile
import os

from . import opexpect
from . import system
from . import openpower

from .system import BaseSystem, ConsoleState as SysConsoleState
from .exceptions import CommandFailed
from .petitboot import PetitbootState
from .console import Console, ConsoleState

from . import logger
log = logger.optest_logger_glob.get_logger(__name__)

class QemuConsole(Console):
    def __init__(self, logfile):
        self.qemu_pty = None

        # The "host console" for a QemuSystem comes from the pty created by
        # pexpect for the qemu process. To match the behaviour of a "real" host
        # console we need to blackhole any writes made while the host is off
        # (i.e. qemu isn't running). To do that we have a seperate pty with
        # cat and we swap between the two as qemu starts and stops.
        self.cat_pty = pexpect.spawn("cat - >/dev/null", echo=False)

        super().__init__(logfile=logfile)

    def set_pty(self, pty):
        self.qemu_pty = pty
        # hmm, maybe we should check the connected state?
        self.pty = pty

    def connect(self):
        # TODO: Since this is a host console we should be able to connect
        # even when the host is "off". We'd need to ensure that we blackhole
        # any terminal interactions because the pexpect session lifetime is
        # tied to that of the qemu process (i think? it might just EOF)
        if self.qemu_pty:
            self.pty = self.qemu_pty
        else:
            self.pty = self.cat_pty

        self.state = ConsoleState.CONNECTED

    def close(self):
        self.pty = None
        self.state = ConsoleState.DISCONNECTED
        # FIXME: do we need to call super().close()?

    def is_connected(self):
        return self.state == ConsoleState.CONNECTED

qemu_state_table = [
    SysConsoleState('skiboot', openpower.skiboot_entry, 10, openpower.skiboot_exit, 30),
    # pb entry timeout is 60s because the default pb config is to supress dmesg
    PetitbootState('petitboot', 60, 30),
]

class QemuSystem(BaseSystem):
    def __init__(self, **kwargs):
        self.qemu_binary = kwargs.get('qemu_binary')
        self.initramfs = kwargs.get('initramfs')
        self.skiboot = kwargs.get('skiboot')
        self.kernel = kwargs.get('kernel')
        self.cdrom = kwargs.get('cdrom')
        self.disks = kwargs.get('disks')
        self.pnor = kwargs.get('pnor')

        self.logfile = kwargs.get('logfile', sys.stdout) # FIXME?
        self.skip_pci = kwargs.get('no_pci', False)
        self.fru_path = kwargs.get('fru_path')

        self.qemu_running = False
        self.mac_str = '52:54:00:22:34:56'

        self.console = QemuConsole(self.logfile)

        super().__init__(None, console=self.console, host=kwargs.get('host'))

        for s in qemu_state_table:
            self._add_state(s)

    def bmc_is_alive(self):
        return True

    def host_power_on(self):
        log.debug("QEMU Power on")

        cmd = ("%s" % (self.qemu_binary)
               + " -machine powernv -m 4G"
               + " -nographic -nodefaults"
               )
        if self.pnor:
            cmd = cmd + " -drive file={},format=raw,if=mtd".format(self.pnor)
        if self.skiboot:
            skibootdir = os.path.dirname(self.skiboot)
            skibootfile = os.path.basename(self.skiboot)
            if skibootfile:
                cmd = cmd + " -bios %s" % (skibootfile)
            if skibootdir:
                cmd = cmd + " -L %s" % (skibootdir)
        if self.kernel:
            cmd = cmd + " -kernel %s" % (self.kernel)
            if self.initramfs:
                cmd = cmd + " -initrd %s" % (self.initramfs)

        # So in the powernv QEMU model we have 3 PHBs with one slot free each.
        # We can add a pcie bridge to each of these, and each bridge has 31
        # slots.. if you see where I'm going..
        if self.skip_pci:
            cmd = cmd + " -global driver=power9_v2.0-pnv-chip,property=num-phbs,value=0"
        else:
            cmd = (cmd
                   + " -device pcie-pci-bridge,id=pcie.3,bus=pcie.0,addr=0x0"
                   + " -device pcie-pci-bridge,id=pcie.4,bus=pcie.1,addr=0x0"
                   + " -device pcie-pci-bridge,id=pcie.5,bus=pcie.2,addr=0x0"
                   )

            # Put the NIC in slot 2 of the second PHB (1st is reserved for later)
            cmd = (cmd
                   + " -netdev user,id=u1 -device e1000e,netdev=u1,mac={},bus=pcie.4,addr=2"
                   .format(self.mac_str)
                   )
            prefilled_slots = 1

            if self.cdrom is not None:
                # Put the CDROM in slot 3 of the second PHB
                cmd = (cmd
                       + " -drive file={},id=cdrom01,if=none,media=cdrom".format(self.cdrom)
                       + " -device virtio-blk-pci,drive=cdrom01,id=virtio02,bus=pcie.4,addr=3"
                       )
                prefilled_slots += 1

            bridges = []
            bridges.append({'bus': 3, 'n_devices': 0, 'bridged': False})
            bridges.append(
                {'bus': 4, 'n_devices': prefilled_slots, 'bridged': False})
            bridges.append({'bus': 5, 'n_devices': 0, 'bridged': False})

            # For any amount of disks we have, start finding spots for them in the PHBs
            if self.disks:
                diskid = 0
                bid = 0
                for disk in self.disks:
                    bridge = bridges[bid]
                    if bridge['n_devices'] >= 30:
                        # This bridge is full
                        if bid == len(bridges) - 1:
                            # All bridges full, find one to extend
                            if [x for x in bridges if x['bridged'] == False] == []:
                                # We messed up and filled up all our slots
                                raise OpTestError("Oops! We ran out of slots!")
                            for i in range(0, bid):
                                if not bridges[i]['bridged']:
                                    # We can add a bridge here
                                    parent = bridges[i]['bus']
                                    new = bridges[-1]['bus'] + 1
                                    print(("Adding new bridge {} on bridge {}".format(
                                        new, parent)))
                                    bridges.append(
                                        {'bus': new, 'n_devices': 0, 'bridged': False})
                                    cmd = cmd + \
                                        " -device pcie-pci-bridge,id=pcie.{},bus=pcie.{},addr=0x1".format(
                                            new, parent)
                                    bid = bid + 1
                                    bridges[i]['bridged'] = True
                                    bridge = bridges[bid]
                                    break
                        else:
                            # Just move to the next one, subsequent bridge should
                            # always have slots
                            bid = bid + 1
                            bridge = bridges[bid]
                            if bridge['n_devices'] >= 30:
                                raise OpTestError("Lost track of our PCI bridges!")

                    # Got a bridge, let's go!
                    # Valid bridge slots are 1..31, but keep 1 free for more bridges
                    addr = 2 + bridge['n_devices']
                    print(("Adding disk {} on bus {} at address {}".format(
                        diskid, bridge['bus'], addr)))
                    cmd = cmd + \
                        " -drive file={},id=disk{},if=none".format(
                            disk.name, diskid)
                    cmd = cmd + " -device virtio-blk-pci,drive=disk{},id=virtio{},bus=pcie.{},addr={}".format(
                        diskid, diskid, bridge['bus'], hex(addr))
                    diskid += 1
                    bridge['n_devices'] += 1


#       FIXME: old code I ahcked up to remove the OpTestConfig dependency,
#              leaving it here so we know the source of fru_data is.
#       if self.fru_path:
#        fru_path = os.path.join(
#            OpTestConfiguration.conf.basedir, "test_binaries", "qemu_fru")


        # FIXME: this seems to be broken. not sure why
        cmd = cmd + " -device ipmi-bmc-sim,id=bmc0"
        if self.fru_path:
            cmd += ",frudatafile=" + self.fru_path
        cmd = cmd + " -device isa-ipmi-bt,bmc=bmc0,irq=10"
        cmd = cmd + " -serial none -device isa-serial,chardev=s1 -chardev stdio,id=s1,signal=off"
        cmd = cmd + " -no-reboot"

        log.info("Qemu command: {}".format(cmd))
        print(cmd)

        # ok, now run qemu and setup our console
        try:
            # HACK: Use the QemuConsole object's logfile so that the console
            # recording facility works. This is a bit gross, but since the
            # console is tied to the stdio of the main qemu process, which we
            # launch here, we have to.
            #
            # We could fix this by making the qemu console a seperate pty and
            # attach to it by having QemuConsole spawn screen.
            pty = opexpect.spawn(cmd, logfile=self.console.logfile)

            # HACK: when passed a bad cmdline qemu can take a sec bail, so just wait
            # if we can make it start with the CPUs not executing we might be able to
            # do something more intelligent, but w/e this works for now
            time.sleep(0.5)
            if not pty.isalive():
                raise CommandFailed(cmd, pty.read(), pty.status)

            pty.setwinsize(1000, 1000)
#            if self.delaybeforesend:
#                pty.delaybeforesend = self.delaybeforesend
        except Exception as e:
            log.info("Qemu command failed")
            raise e

        # update the pty in the qemu console so it's pointing at the right place
        self.console.set_pty(pty)
        self.qemu_running = True

    def host_power_off(self):
        if self.qemu_running:
            self.console.pty.close()
            self.qemu_running = False

    def host_power_is_on(self):
        if self.qemu_running:
            return self.console.pty.isalive()
        return False


# stuff from the old qemu that we should probably delete
'''
need to do something with the disk crap
class OpTestQemu():
    def __init__(self, conf=None, qemu_binary=None, pnor=None, skiboot=None,
                 kernel=None, initramfs=None, cdrom=None,
                 logfile=sys.stdout):
        self.disks = []
        # need the conf object to properly bind opened object
        # we need to be able to cleanup/close the temp file in signal handler
        self.conf = conf
        if self.conf.args.qemu_scratch_disk and self.conf.args.qemu_scratch_disk.strip():
            try:
                # starts as name string
                log.debug("OpTestQemu opening file={}"
                          .format(self.conf.args.qemu_scratch_disk))
                self.conf.args.qemu_scratch_disk = \
                    open(self.conf.args.qemu_scratch_disk, 'wb')
                # now is a file-like object
            except Exception as e:
                log.error("OpTestQemu encountered a problem "
                          "opening file={} Exception={}"
                          .format(self.conf.args.qemu_scratch_disk, e))
        else:
            # update with new object to close in cleanup
            self.conf.args.qemu_scratch_disk = \
                tempfile.NamedTemporaryFile(delete=True)
            # now a file-like object
            try:
                create_hda = subprocess.check_call(["qemu-img", "create",
                                                    "-fqcow2",
                                                    self.conf.args.qemu_scratch_disk.name,
                                                    "10G"])
            except Exception as e:
                log.error("OpTestQemu encountered a problem with qemu-img,"
                          " check that you have qemu-utils installed first"
                          " and then retry.")
                raise e

        self.disks.append(self.conf.args.qemu_scratch_disk)

'''
