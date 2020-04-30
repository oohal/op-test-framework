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

from . import OpExpect
from . import newersys

from .newersys import SysState, BaseSystem
from .Exceptions import CommandFailed
from .OpTestConsole import OpTestConsole, ConsoleState

from . import OpTestLogger
log = OpTestLogger.optest_logger_glob.get_logger(__name__)

qemu_state_table = [
    SysState('skiboot', False, newersys.skiboot_expect_table, 120),
    SysState('petitboot', False, newersys.pb_expect_table, 120),
]

class QemuConsole(OpTestConsole):
    def __init__(self):
        self.qemu_pty = None
        super().__init__()

    def set_pty(self, pty):
        self.qemu_pty = pty
        self.pty = pty

    def connect(self):
        # TODO: since this is a host console we should be able to connect
        # even when the host is "off". We'd need to ensure that we blackhole
        # any terminal interactions because the pexpect session lifetime is
        # tied to that of the qemu process (i think? it might just EOF)
        if not self.qemu_pty:
            raise Exception("Can't connect the console unless Qemu is running")
        self.state = ConsoleState.CONNECTED
    def close(self):
        self.state = ConsoleState.DISCONNECTED
    def is_connected(self):
        return True

class QemuSystem(BaseSystem):
    def __init__(self, pnor, kernel, initramfs, qemu_binary="qemu-system-ppc64",
                 skiboot=None, disks=None, cdrom=None, fru_path=None):
        self.qemu_binary = qemu_binary
        self.pnor = pnor
        self.skiboot = skiboot
        self.kernel = kernel
        self.initramfs = initramfs
        self.disks = disks
        self.logfile = sys.stdout # FIXME?
        self.system = None
        self.cdrom = cdrom

        self.mac_str = '52:54:00:22:34:56'
        self.fru_path = None

        self.skip_pci = True

        self.qemu_running = False
        con = QemuConsole()

        # TODO: host object?
        super().__init__(None, con)

        for s in qemu_state_table:
            self._add_state(s)

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
        if not self.skip_pci:
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


#       old code I ahcked up to remove the OpTestConfig dependency
#        fru_path = os.path.join(
#            O pTestConfiguration.conf.basedir, "test_binaries", "qemu_fru")

        # typical host ip=10.0.2.2 and typical skiroot 10.0.2.15
        # use skiroot as the source, no sshd in skiroot
#        cmd = cmd + " -device ipmi-bmc-sim,id=bmc0"
#        if self.fru_path:
#            cmd += ",frudatafile=" + self.fru_path
#        cmd = cmd + " -device isa-ipmi-bt,bmc=bmc0,irq=10"
        cmd = cmd + " -serial none -device isa-serial,chardev=s1 -chardev stdio,id=s1,signal=off"

        cmd = cmd + " -no-reboot"

        log.info("Qemu command: {}".format(cmd))
        print(cmd)

        # ok, now run qemu and setup our console
        try:
            pty = OpExpect.spawn(cmd, logfile=self.logfile)
            time.sleep(0.2)
            if not pty.isalive():
                raise CommandFailed(cmd, pty.read(), pty.status)

            pty.setwinsize(1000, 1000)
#            if self.delaybeforesend:
#                pty.delaybeforesend = self.delaybeforesend
        except Exception as e:
            log.info("Qemu command failed")
            raise e

        self.console.set_pty(pty)
        self.qemu_running = True

    def host_power_off(self):
        # FIXME: kill qemu
        pass

    def host_power_is_on(self):
        return self.qemu_running


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
