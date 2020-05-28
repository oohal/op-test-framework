#!/usr/bin/env python3
# encoding=utf8
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/common/OpTestIPMI.py $
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2015
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
#
# IBM_PROLOG_END_TAG

'''
OpTestIPMI
----------

IPMI package which contains all BMC related IPMI commands

This class encapsulates all function which deals with the BMC over IPMI
in OpenPower systems
'''

import time
import subprocess
import os
import pexpect
import logging
import sys
import re

from .constants import Constants as BMC_CONST
#from .OpTestUtil import OpTestUtil
#from . import OpTestSystem
from .exceptions import CommandFailed, BMCDisconnected, OpTestError
from . import opexpect
from .console import Console, ConsoleState

log = logging.getLogger(__name__)


class IPMITool():
    '''
    Run (locally) some command using ipmitool.

    This wrapper class takes care of all the login/method details for
    the caller.
    '''

    def __init__(self, method='lanplus', binary='ipmitool',
                 ip=None, username=None, password=None):
        self.method = 'lanplus'
        self.ip = ip
        self.username = username
        self.password = password
        self.binary = binary

    def binary_name(self):
        return self.binary

    def arguments(self):
        s = ' -H %s -I %s' % (self.ip, self.method)
        if self.username:
            s += ' -U %s' % (self.username)
        if self.password:
            s += ' -P %s' % (self.password)
        s += ' '
        return s

    def run(self, cmd, background=False, cmdprefix=None):
        '''
        Run a ipmitool cmd.

        :throws: :class:`common.Execptions.CommandFailed`
        '''
        if cmdprefix:
            cmd = cmdprefix + self.binary + " " + self.arguments() + cmd
        else:
            cmd = self.binary + self.arguments() + cmd
        log.info(cmd)
        if background:
            try:
                child = subprocess.Popen(
                    cmd, shell=True, universal_newlines=True, encoding='utf-8')
            except Exception as e:
                raise CommandFailed(
                    "Unable to spawn process {}".format(cmd), e, -1)
            return child
        else:
            # TODO - need python 2.7
            # output = check_output(cmd, stderr=subprocess.STDOUT, shell=True)
            try:
                cmd = subprocess.Popen(cmd, stderr=subprocess.STDOUT,
                                       stdout=subprocess.PIPE, shell=True,
                                       universal_newlines=True, encoding='utf-8')
            except:
                raise CommandFailed(cmd, "Failed to spawn subprocess", -1)
            output = cmd.communicate()[0]

            log.info("ipmitool output={}".format(output).strip())
            return output


# FIXME: move this to the supermicro specific BMC file
class pUpdate():
    def __init__(self, method='lan', binary='pUpdate',
                 ip=None, username=None, password=None):
        self.method = 'lan'
        self.ip = ip
        self.username = username
        self.password = password
        self.binary = binary

    def set_binary(self, binary):
        self.binary = binary

    def binary_name(self):
        return self.binary

    def arguments(self):
        s = ' -h %s -i %s' % (self.ip, self.method)
        if self.username:
            s += ' -u %s' % (self.username)
        if self.password:
            s += ' -p %s' % (self.password)
        s += ' '
        return s

    def run(self, cmd, background=False, cmdprefix=None):
        if cmdprefix:
            cmd = cmdprefix + self.binary + self.arguments() + cmd
        else:
            cmd = self.binary + self.arguments() + cmd
        log.debug("Running pUpdate cmd={}".format(cmd))
        if background:
            try:
                child = subprocess.Popen(
                    cmd, shell=True, universal_newlines=True, encoding='utf-8')
            except:
                l_msg = "pUpdate Command Failed: {}".format(cmd)
                log.error(l_msg)
                raise OpTestError(l_msg)
            return child
        else:
            # TODO - need python 2.7
            # output = check_output(cmd, stderr=subprocess.STDOUT, shell=True)
            try:
                cmd = subprocess.Popen(cmd, stderr=subprocess.STDOUT,
                                       stdout=subprocess.PIPE, shell=True,
                                       universal_newlines=True, encoding='utf-8')
            except:
                l_msg = "pUpdate Command Failed: {}".format(cmd)
                log.error(l_msg)
                raise OpTestError(l_msg)
            output = cmd.communicate()[0]
            log.debug(output)
            return output


class IPMIConsole(Console):
    def __init__(self, ipmitool=None, log=None, prompt=None,
                 delaybeforesend=None):
        self.ipmitool = ipmitool
        self.delaybeforesend = delaybeforesend
        super().__init__(log, None)

    def close(self):
        if self.state == ConsoleState.DISCONNECTED:
            return
        try:
            self.pty.send("\r")
            self.pty.send('~.')
            close_rc = self.pty.expect(
                ['[terminated ipmitool]', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            log.debug("CLOSE Expect Buffer ID={}".format(hex(id(self.pty))))
            rc_child = self.pty.close()
            self.state = ConsoleState.DISCONNECTED
            exitCode = signalstatus = None
            if self.pty.status != -1:  # leaving for future debug
                if os.WIFEXITED(self.pty.status):
                    exitCode = os.WEXITSTATUS(self.pty.status)
                else:
                    signalstatus = os.WTERMSIG(self.pty.status)
        except pexpect.ExceptionPexpect:
            self.state = ConsoleState.DISCONNECTED
            raise OpTestError("IPMI: failed to close ipmi console")
        except Exception as e:
            self.state = ConsoleState.DISCONNECTED
            pass

    def connect(self, logger=None):
        if self.state == ConsoleState.CONNECTED:
            raise 're-opening connected console'  # FIXME: handle properly
            rc_child = self.close()

        try:
            self.ipmitool.run('sol deactivate')
        except OpTestError:
            log.info('SOL already deactivated')

        cmd = self.ipmitool.binary_name() + self.ipmitool.arguments() + ' sol activate'
        try:
            self.pty = opexpect.spawn(cmd, logfile=self.logfile)
        except Exception as e:
            self.state = ConsoleState.DISCONNECTED
            raise CommandFailed(
                'opexpect.spawn', "opexpect.spawn encountered a problem, command was '{}'".format(cmd), -1)

        log.debug("#IPMI SOL CONNECT")
        self.pty.setwinsize(1000, 1000)

#        # XXX: why is this setting .logfile_read and not .logfile?
        self.pty.logfile_read = self.logfile

        if self.delaybeforesend:
            self.pty.delaybeforesend = self.delaybeforesend
        rc = self.pty.expect_exact(
            ['[SOL Session operational.  Use ~? for help]', pexpect.TIMEOUT, pexpect.EOF], timeout=10)

        log.debug("rc={}".format(rc))
        if rc == 0:
            time.sleep(0.2)
            log.debug("CONNECT starts Expect Buffer ID={}".format(hex(id(self.pty))))
            self.state = ConsoleState.CONNECTED
            return self.pty

        if rc == 1:
            self.pty.close()
            time.sleep(60)  # give things a minute to clear ???????????????????
            raise CommandFailed('sol activate',
                                "IPMI: pexpect.TIMEOUT while trying to establish"
                                " connection, command was '{}'"
                                .format(cmd), -1)
        if rc == 2:
            self.pty.close()
            time.sleep(60)  # give things a minute to clear ????????????????????
            raise CommandFailed('sol activate',
                                "IPMI: insufficient resources for session, unable"
                                " to establish IPMI v2 / RMCP+ session, command was '{}'"
                                .format(cmd), -1)


class OpTestIPMI():
    def __init__(self, i_bmcIP, i_bmcUser, i_bmcPwd, log=log,
                 delaybeforesend=None):
        self.cv_bmcIP = i_bmcIP
        self.cv_bmcUser = i_bmcUser
        self.cv_bmcPwd = i_bmcPwd
        self.ipmitool = IPMITool(method='lanplus',
                                 ip=i_bmcIP,
                                 username=i_bmcUser,
                                 password=i_bmcPwd)
        self.pUpdate = pUpdate(method='lan',
                               ip=i_bmcIP,
                               username=i_bmcUser,
                               password=i_bmcPwd)
        self.console = IPMIConsole(ipmitool=self.ipmitool,
                                   log=log,
                                   delaybeforesend=delaybeforesend)

    def get_sol_console(self):
        '''
        Get the IPMIConsole object, to run commands on the host etc.
        '''
        return self.console

    def ipmi_sdr_clear(self):
        '''
        This function clears the sensor data.
        '''
        output = self.ipmitool.run('sel clear')
        if 'Clearing SEL' in output:
            # FIXME: This code should instead check for 'erasure completed'
            #        and the status of the erasure, rather than this crude loop
            retries = 20
            while (retries > 0):
                output = self.ipmitool.run('sel elist')
                if 'no entries' in output:
                    return BMC_CONST.FW_SUCCESS
                else:
                    l_msg = "Sensor data still has entries!"
                    log.error(l_msg)
                    retries -= 1
                    if (retries == 0):
                        raise OpTestError(l_msg)
                    time.sleep(1)
        else:
            l_msg = "Clearing the sensor data Failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_power_off(self):
        '''
        This function sends the chassis power off ipmitool command.
        '''
        output = self.ipmitool.run('chassis power off')
        if 'Down/Off' in output:
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power OFF Failed: {}".format(output)
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_power_on(self):
        '''
        This function sends the chassis power on ipmitool command
        '''
        output = self.ipmitool.run('chassis power on')
        if 'Up/On' in output:
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power ON Failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_power_soft(self):
        '''
        This function sends the chassis power soft ipmitool command
        '''
        output = self.ipmitool.run('chassis power soft')
        time.sleep(BMC_CONST.SHORT_WAIT_IPL)
        if "Chassis Power Control: Soft" in output:
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power Soft Failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_power_cycle(self):
        '''
        This function sends the chassis power cycle ipmitool command
        '''
        output = self.ipmitool.run('chassis power cycle')
        time.sleep(BMC_CONST.SHORT_WAIT_IPL)
        if "Chassis Power Control: Cycle" in output:
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power Cycle Failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_power_reset(self):
        '''
        This function sends the chassis power reset ipmitool command.
        '''
        r = self.ipmitool.run('chassis power reset')
        self.console.close()
        if not BMC_CONST.CHASSIS_POWER_RESET in r:
            raise Exception("IPMI 'chassis power reset' failed: %s " % r)

    def ipmi_power_diag(self):
        '''
        This function sends the chassis power diag ipmitool command.
        '''
        r = self.ipmitool.run('chassis power diag')
        if not "Chassis Power Control: Diag" in r:
            raise Exception("IPMI 'chassis power diag' failed: %s " % r)

    ##
    #
    # @return BMC_CONST.FW_SUCCESS or raise OpTestError
    #

    def ipl_wait_for_working_state(self, timeout=10):
        '''
        This function starts the sol capture and waits for the IPL to end. The
        marker for IPL completion is the Host Status sensor which reflects the ACPI
        power state of the system.  When it reads S0/G0: working it means that the
        petitboot is has began loading.  The overall timeout for the IPL is defined
        in the test configuration options.

        :param timeout: The number of minutes to wait for IPL to complete,
                        i.e. How long to poll the ACPI sensor for working
                        state before giving up.
        :type timeout: int
        '''
        timeout = time.time() + 60*timeout
        cmd = 'sdr elist |grep \'Host Status\''
        output = self.ipmitool.run(cmd)
        if not "Host Status" in output:
            return BMC_CONST.FW_PARAMETER
        while True:
            output = self.ipmitool.run(cmd)
            if 'S0/G0: working' in output:
                log.debug("Host Status is S0/G0: working, IPL finished")
                break
            if time.time() > timeout:
                l_msg = "IPL timeout"
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(5)

        try:
            self.ipmitool.run('sol deactivate')
            self.console.close()
        except subprocess.CalledProcessError:
            l_msg = 'SOL already deactivated'
            log.error(l_msg)
            self.console.close()
            raise OpTestError(l_msg)
        return BMC_CONST.FW_SUCCESS

    def ipmi_ipl_wait_for_working_state_v1(self, timeout=10):
        '''
        This function waits for the IPL to end. The marker for IPL completion is the
        Host Status sensor which reflects the ACPI power state of the system.  When it
        reads S0/G0: working it means that the petitboot is has began loading.

        :param timeout: The number of minutes to wait for IPL to complete,
                        i.e. How long to poll the ACPI sensor for working
                        state before giving up.
        :type timeout: int
        '''
        timeout = time.time() + 60*timeout
        cmd = 'sdr elist |grep \'Host Status\''
        output = self.ipmitool.run(cmd)
        if not "Host Status" in output:
            return BMC_CONST.FW_PARAMETER

        while True:
            if 'S0/G0: working' in output:
                log.debug("Host Status is S0/G0: working, IPL finished")
                break
            if time.time() > timeout:
                l_msg = "IPL timeout"
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(5)
            output = self.ipmitool.run(cmd)
        return BMC_CONST.FW_SUCCESS

    def ipmi_wait_for_standby_state(self, i_timeout=120):
        '''
        This function waits for system to reach standby state or soft off. The
        marker for standby state is the Host Status sensor which reflects the ACPI
        power state of the system.  When it reads S5/G2: soft-off it means that the
        system reached standby or soft-off state. The overall timeout for the standby is defined
        in the test configuration options.

        :param i_timeout: The number of seconds to wait for system to reach standby,
                          i.e. How long to poll the ACPI sensor for soft-off
                          state before giving up.
        :type i_timeout: int
        '''
        l_timeout = time.time() + i_timeout
        l_cmd = ' power status '
        wait_for = 'Chassis Power is off'
        while True:
            l_output = self.ipmitool.run(l_cmd)
            if wait_for in l_output:
                log.debug("Host power is off, system reached standby")
                break
            if time.time() > l_timeout:
                l_msg = "Standby timeout"
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(BMC_CONST.SHORT_WAIT_STANDBY_DELAY)

        return BMC_CONST.FW_SUCCESS

    def ipmi_wait_for_os_boot_complete(self, i_timeout=10):
        '''
        This function waits for the Host OS Boot(IPL) to end. The
        marker for IPL completion is the OS Boot sensor which reflects status
        of host OS Boot. When it reads boot completed it means that the
        Host OS Booted successfully.  The overall timeout for the IPL is defined
        in the test configuration options.

        :param i_timeout: The number of minutes to wait for IPL to complete or Boot time,
                          i.e. How long to poll the OS Boot sensor for working
                          state before giving up.
        :type i_timeout: int
        '''
        l_timeout = time.time() + 60*i_timeout
        l_cmd = 'sdr elist |grep \'OS Boot\''
        output = self.ipmitool.run(l_cmd)
        if not "OS Boot" in output:
            return BMC_CONST.FW_PARAMETER
        while True:
            l_output = self.ipmitool.run(l_cmd)
            if BMC_CONST.OS_BOOT_COMPLETE in l_output:
                log.debug("Host OS is booted")
                break
            if time.time() > l_timeout:
                l_msg = "IPL timeout"
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(BMC_CONST.SHORT_WAIT_IPL)

        return BMC_CONST.FW_SUCCESS

    def ipmi_wait_for_os_boot_complete_v1(self, i_timeout=10):
        '''
        This function waits for the Host OS Boot(IPL) to end. The
        marker for IPL completion is the OS Boot sensor which reflects status
        of host OS Boot. When it reads boot completed it means that the
        Host OS Booted successfully.

        :param i_timeout: The number of minutes to wait for IPL to complete or Boot time,
              i.e. How long to poll the OS Boot sensor for working state before giving up.
        :type i_timeout: int
        '''
        l_timeout = time.time() + 60*i_timeout
        l_cmd = 'sdr elist |grep \'OS Boot\''
        l_output = self.ipmitool.run(l_cmd)
        if not "OS Boot" in l_output:
            return BMC_CONST.FW_PARAMETER

        while True:
            if BMC_CONST.OS_BOOT_COMPLETE in l_output:
                log.debug("Host OS is booted")
                break
            if time.time() > l_timeout:
                l_msg = "IPL timeout"
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(BMC_CONST.SHORT_WAIT_IPL)
            l_output = self.ipmitool.run(l_cmd)

        return BMC_CONST.FW_SUCCESS

    def ipmi_sel_check(self, i_string="Transition to Non-recoverable"):
        '''
        This function dumps the sel log and looks for specific hostboot error
        log string
        '''
        output = self.ipmitool.run('sel elist')

        # FIXME: should we be doing this? don't we already log the output?
        for line in output:
            log.info(line)

        if i_string in output:
            raise OpTestError('Error log(s) detected during IPL: %s' % output)
        else:
            return BMC_CONST.FW_SUCCESS

    def ipmi_sel_elist(self, dump=False):
        '''
        This function dumps the sel elist
        '''
        output = self.ipmitool.run('sel elist')

        if dump:
            print(
                "\n----------------------------------------------------------------------")
            print("SELs")
            print(
                "----------------------------------------------------------------------")
            print(("{}".format(output)))
            print(
                "----------------------------------------------------------------------")

        return output

    def ipmi_power_status(self):
        '''
        Determines the power status of the bmc

        :returns: Bool: True if the system is powered on.
        '''
        l_output = self.ipmitool.run('chassis power status')
        if('on' in l_output):
            return True
        elif('off' in l_output):
            return False
        else:
            raise OpTestError(
                "Can't recognize chassis power status: " + str(l_output))

    def ipmi_cold_reset(self):
        '''
        Performs a cold reset onto the bmc
        '''
        l_initstatus = self.ipmi_power_status()
        log.debug("Applying Cold reset.")
        rc = self.ipmitool.run(" mc reset cold")
        if "Sent cold reset command to MC" in rc:
            self.console.close()
            time.sleep(BMC_CONST.SHORT_WAIT_IPL)
            utils.ping(
                self.cv_bmcIP, totalSleepTime=BMC_CONST.PING_RETRY_FOR_STABILITY)
            self.ipmi_wait_for_bmc_runtime()
            l_finalstatus = self.ipmi_power_status()
            if (l_initstatus != l_finalstatus):
                log.debug('initial status ' + str(l_initstatus))
                log.debug('final status ' + str(l_finalstatus))
                log.debug('Power status changed during cold reset')
                raise OpTestError('Power status changed')
            return BMC_CONST.FW_SUCCESS
        else:
            log.error("Cold reset failed, rc={}".format(rc))
            raise OpTestError(rc)

    def ipmi_wait_for_bmc_runtime(self, i_timeout=10):
        '''
        This function waits until BMC Boot finishes after a BMC Cold reset

        0x00
          Boot Complete
        0xC0
          Not Complete

        Here AMI systems returns 00 and SMC Systems return NULL for success
        '''
        l_timeout = time.time() + 60*i_timeout
        l_cmd = ' raw 0x3a 0x0a '
        while True:
            try:
                l_output = self.ipmitool.run(l_cmd)
                log.debug(l_output)
            except:
                continue
            if "0xc0"in l_output:
                log.info("BMC Still booting...")
            elif "00" in l_output:  # AMI BMC returns 00 as output
                log.info("BMC Completed booting...")
                break
            else:  # SMC BMC returns empty as output
                log.info("BMC Completed booting...")
                break
            if time.time() > l_timeout:
                l_msg = "BMC Boot timeout..."
                log.error(l_msg)
                raise OpTestError(l_msg)
            time.sleep(BMC_CONST.SHORT_WAIT_IPL)
        return BMC_CONST.FW_SUCCESS

    def ipmi_warm_reset(self):
        '''
        Performs a warm reset onto the bmc
        '''
        l_initstatus = self.ipmi_power_status()

        log.info("Applying Warm reset. Wait for "
                 + str(BMC_CONST.BMC_WARM_RESET_DELAY) + "sec")

        rc = self.ipmitool.run("mc reset warm")
        if "Sent warm reset command to MC" in rc:
            log.info("Warm reset result: {}".format(rc))

            self.console.close()

            time.sleep(BMC_CONST.BMC_WARM_RESET_DELAY)
            utils.ping(
                self.cv_bmcIP, totalSleepTime=BMC_CONST.PING_RETRY_FOR_STABILITY)
            l_finalstatus = self.ipmi_power_status()
            if (l_initstatus != l_finalstatus):
                log.debug('initial status ' + str(l_initstatus))
                log.debug('final status ' + str(l_finalstatus))
                log.debug('Power status changed during cold reset')
                raise OpTestError('Power status changed')
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Warm reset Failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_preserve_network_setting(self):
        '''
        Preserves the network setting
        '''
        log.info("Protecting BMC network setting")
        l_cmd = BMC_CONST.BMC_PRESRV_LAN
        rc = self.ipmitool.run(l_cmd)

        if BMC_CONST.BMC_ERROR_LAN in rc:
            l_msg = "Can't protect setting! Please preserve setting manually"
            log.error(l_msg)
            raise OpTestError(l_msg)

        return BMC_CONST.FW_SUCCESS

    def ipmi_code_update(self, i_image, i_imagecomponent):
        '''
        Flashes image using ipmitool

        :param i_image: hpm file including location
        :param i_imagecomponent: component to be updated from the hpm file
                                 BMC_CONST.BMC_FW_IMAGE_UPDATE
                                 or BMC_CONST.BMC_PNOR_IMAGE
        '''
        self.ipmi_cold_reset()
        time.sleep(5)
        l_cmd = BMC_CONST.BMC_HPM_UPDATE + i_image + " " + i_imagecomponent
        # We need to do a re-try of hpm code update if it fails for the first time
        # As AMI systems are some times failed to flash for the first time.
        count = 0
        while (count < 2):
            self.ipmi_preserve_network_setting()
            time.sleep(5)
            rc = self.ipmitool.run(
                l_cmd, background=False, cmdprefix="echo y |")
            log.info("IPMI code update result: {}".format(rc))
            if(rc.__contains__("Firmware upgrade procedure successful")):
                return BMC_CONST.FW_SUCCESS
            elif count == 1:
                l_msg = "Code Update Failed"
                log.error(l_msg)
                raise OpTestError(l_msg)
            else:
                count = count + 1
                continue

    def ipmi_get_side_activated(self):
        '''
        Get information on active sides for both BMC and PNOR

        - 0x0080 indicates primary side is activated
        - 0x0180 indicates golden side is activated

        :returns: the active sides for BMC and PNOR chip (that are either primary of golden)
                  l_bmc_side, l_pnor_side
        '''

        l_result = self.ipmitool.run(
            BMC_CONST.BMC_ACTIVE_SIDE).strip().split('\n')

        for i in range(len(l_result)):
            if('BIOS' in l_result[i]):
                if(l_result[i].__contains__(BMC_CONST.PRIMARY_SIDE)):
                    log.info("Primary side of PNOR is active")
                    l_pnor_side = BMC_CONST.PRIMARY_SIDE
                elif(BMC_CONST.GOLDEN_SIDE in l_result[i]):
                    log.info("Golden side of PNOR is active")
                    l_pnor_side = BMC_CONST.GOLDEN_SIDE
                else:
                    l_msg = "Error determining active side: " + l_result
                    log.error(l_msg)
                    raise OpTestError(l_msg)
            elif('BMC' in l_result[i]):
                if(l_result[i].__contains__(BMC_CONST.PRIMARY_SIDE)):
                    log.info("Primary side of BMC is active")
                    l_bmc_side = BMC_CONST.PRIMARY_SIDE
                elif(BMC_CONST.GOLDEN_SIDE in l_result[i]):
                    log.info("Golden side of BMC is active")
                    l_bmc_side = BMC_CONST.GOLDEN_SIDE
                else:
                    l_msg = "Error determining active side: " + l_result
                    log.error(l_msg)
                    raise OpTestError(l_msg)
            else:
                l_msg = "Error determining active side: " + + l_result
                log.error(l_msg)
                raise OpTestError(l_msg)

        return l_bmc_side, l_pnor_side

    def ipmi_get_PNOR_level(self):
        '''
        Get PNOR level
        '''
        l_rc = self.ipmitool.run(BMC_CONST.BMC_MCHBLD)
        return l_rc

    def ipmi_get_bmc_golden_side_version(self):
        '''
        This function gets the BMC golden side firmware version.
        Below are the fields to decode the version of firmware

        1. Completion code

           - 0x00 – success
           - 0x81 – Not a valid image in golden SPI.
           - 0xff – Reading Golden side SPI failed.

        2. Device ID (0x02)
        3. IPMI Dev version (0x01)
        4. Firmware Revision 1 (Major )
        5. Firmware Revision 2 (Minor)
        6. IPMI Version
        7. Additional Device support refer IPMI spec.
        8. Manufacture ID
        9. Manufacture ID
        10. Manufacture ID
        11. Product ID
        12. Product ID
        13. Auxiliary Firmware Revision
        14. Auxiliary Firmware Revision
        15. Auxiliary Firmware Revision
        16. Auxiliary Firmware Revision

        :returns: BMC golden side firmware version

        ::

         ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x1a
                   20 01 02 16 02 bf 00 00 00 bb aa 4d 4c 01 00
        '''
        log.debug("IPMI: Getting the BMC Golden side version")
        l_rc = self.ipmitool.run(BMC_CONST.IPMI_GET_BMC_GOLDEN_SIDE_VERSION)
        return l_rc

    def ipmi_get_pnor_partition_size(self, i_part):
        '''
        This function gets the size of pnor partition

        :param i_part: partition name to retrieve the size.
                       partition can be NVRAM, GUARD and BOOTKERNEL

        TODO: Add support for remaining partitions.

        :returns: size of partition raise OpTestError when fails

        ::
          ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x0c
          0x42 0x4f 0x4f 0x54 0x4b 0x45 0x52 0x4e 0x45 0x4c 0x00 0x00 0x00 0x00 0x0 0x0 0x0
          00 00 f0 00

        This function will return "00 00 f0 00"
        '''
        log.debug("IPMI: Getting the size of %s PNOR Partition" % i_part)
        if i_part == BMC_CONST.PNOR_NVRAM_PART:
            l_rc = self.ipmitool.run(BMC_CONST.IPMI_GET_NVRAM_PARTITION_SIZE)
        elif i_part == BMC_CONST.PNOR_GUARD_PART:
            l_rc = self.ipmitool.run(BMC_CONST.IPMI_GET_GUARD_PARTITION_SIZE)
        elif i_part == BMC_CONST.PNOR_BOOTKERNEL_PART:
            l_rc = self.ipmitool.run(
                BMC_CONST.IPMI_GET_BOOTKERNEL_PARTITION_SIZE)
        else:
            l_msg = "please provide valid partition eye catcher name ({} is invalid)".format(
                i_part)
            log.error(l_msg)
            raise OpTestError(l_msg)
        return l_rc

    def ipmi_get_bmc_boot_completion_status(self):
        '''
        This function is used to check whether BMC Completed Booting.

        BMC Booting Status:

        00h
          Booting Completed.
        C0h
          Still Booting.

        :returns: output of command or raise OpTestError

        ::

            ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x0a
              00

        It returns 00 if BMC completed booting else it gives C0
        '''
        log.debug("IPMI: Getting the BMC Boot completion status")
        l_res = self.ipmitool.run(BMC_CONST.IPMI_HAS_BMC_BOOT_COMPLETED)
        return l_res

    def ipmi_get_fault_led_state(self):
        '''
        This command is used to get the State of Fault RollUP LED. ::

                Fault RollUP LED      0x00

        :returns: output of command or raise OpTestError

        ::
            ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x02 0x00
                00

            LED State Table: Below are the states it can get
                    0x0  LED OFF
                    0x1  LED ON
                    0x2  LED Standby Blink Rate
                    0x3  LED Slow Blink rate.
        '''
        log.debug("IPMI: Getting the fault rollup LED state")
        l_res = self.ipmitool.run(BMC_CONST.IPMI_GET_LED_STATE_FAULT_ROLLUP)
        return l_res

    def ipmi_get_power_on_led_state(self):
        '''
        This command is used to get the State of Power ON LED. ::

          Power ON LED      0x01

        :returns: output of command or raise OpTestError

        ::

           ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x02 0x01
             01

           LED State Table: Below are the states it can get
                    0x0  LED OFF
                    0x1  LED ON
                    0x2  LED Standby Blink Rate
                    0x3  LED Slow Blink rate.
        '''
        log.debug("IPMI: Getting the Power ON LED state")
        l_res = self.ipmitool.run(BMC_CONST.IPMI_GET_LED_STATE_POWER_ON)
        return l_res

    def ipmi_get_host_status_led_state(self):
        '''
        This command is used to get the State of Host Status LED. ::

                Host Status LED       0x02

        :returns: output of command or raise OpTestError

        ::

          ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x02 0x02
            00

          LED State Table: Below are the states it can get
                   0x0  LED OFF
                   0x1  LED ON
                   0x2  LED Standby Blink Rate
                   0x3  LED Slow Blink rate.
        '''
        log.debug("IPMI: Getting the Host status LED state")
        l_res = self.ipmitool.run(BMC_CONST.IPMI_GET_LED_STATE_HOST_STATUS)
        return l_res

    def ipmi_get_chassis_identify_led_state(self):
        '''
        This command is used to get the State of Chassis Identify LED. ::

           Chassis Identify LED  0x03

        :returns: output of command or raise OpTestError

        ::

          ipmitool -I lanplus -H <BMC-IP> -U ADMIN -P admin raw 0x3a 0x02 0x03
            00

          LED State Table: Below are the states it can get
                   0x0  LED OFF
                   0x1  LED ON
                   0x2  LED Standby Blink Rate
                   0x3  LED Slow Blink rate.
        '''
        log.debug("IPMI: Getting the Chassis Identify LED state")
        l_res = self.ipmitool.run(
            BMC_CONST.IPMI_GET_LED_STATE_CHASSIS_IDENTIFY)
        return l_res

    def ipmi_set_led_state(self, i_led, i_state):
        '''
        This function is used to set the state of a given LED.

        :param i_led: led number to set the state.
                      e.g.: LED Number Table to use.

                      ===================== ====
                      ===================== ====
                      Fault RollUP LED      0x00
                      Power ON LED          0x01
                      Host Status LED       0x02
                      Chassis Identify LED  0x03
                      ===================== ====

        :param i_state: state of led to set.
                        LED State to be set.

                        === =======================
                        === =======================
                        0x0 LED OFF
                        0x1 LED ON
                        0x2 LED Standby Blink Rate
                        0x3 LED Slow Blink rate.
                        === =======================
        '''
        l_led = i_led
        l_state = i_state
        log.debug("IPMI: Setting the %s LED with %s state" % (l_led, l_state))
        l_cmd = "raw 0x3a 0x03 %s %s" % (l_led, l_state)
        l_res = self.ipmitool.run(l_cmd)
        if "00" in l_res:
            log.debug("Set LED state got success")
            return BMC_CONST.FW_SUCCESS
        elif "0x90" in l_res:
            log.error("Invalid LED number (i_led={},i_state={}) res:{}".format(
                i_led, i_state, l_les))
        else:
            l_msg = "IPMI: Set LED state failed (i_led={},i_state={}) res:{}".format(
                i_led, i_state, l_les)
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_enable_fan_control_task_command(self):
        '''
        This function is used to enable Fan control Task thread running on BMC
        Ex: ``ipmitool raw 0x3a 0x12 0x01``

        :returns: return code of command or raise OpTestError when fails

        Completion Code:

        00h
          success
        cch
          Invalid Request Data
        83h
          File not created in start case.
        80h
          Invalid Operation Mode
        '''
        log.debug("IPMI: Enabling the Fan control task thread state")
        l_rc = self.ipmitool.run(BMC_CONST.IPMI_ENABLE_FAN_CONTROL_TASK_THREAD)
        return l_rc

    def ipmi_disable_fan_control_task_command(self):
        '''
        This function is used to disable Fan control Task thread running on BMC
        Ex: ``ipmitool raw 0x3a 0x12 0x00``

        :returns: return code of command or raise OpTestError when fails

        Completion Code:

        00h
          success
        cch
          Invalid Request Data
        83h
          File not created in start case.
        80h
          Invalid Operation Mode
        '''
        log.debug("IPMI: Disabling the Fan control task thread state")
        l_rc = self.ipmitool.run(
            BMC_CONST.IPMI_DISABLE_FAN_CONTROL_TASK_THREAD)
        return l_rc

    def ipmi_get_fan_control_task_state_command(self):
        '''
        This function is used to get the state of fan control task thread.
        Ex: ``ipmitool -I lanplus -U admin -P admin -H <BMC IP> raw 0x3a 0x13``
            returns 00 or 01, depending on state.

        :returns: IPMI_FAN_CONTROL_THREAD_RUNNING = "01",
                  IPMI_FAN_CONTROL_THREAD_NOT_RUNNING = "00"
                  If fan control loop is running it will return "01"
                  else it will return "00"
        '''
        log.debug("IPMI: Getting the state of fan control task thread")
        l_rc = self.ipmitool.run(BMC_CONST.IPMI_FAN_CONTROL_TASK_THREAD_STATE)
        if BMC_CONST.IPMI_FAN_CONTROL_THREAD_NOT_RUNNING in l_rc:
            log.info("IPMI: Fan control task thread state is not running")
            l_state = BMC_CONST.IPMI_FAN_CONTROL_THREAD_NOT_RUNNING
        elif BMC_CONST.IPMI_FAN_CONTROL_THREAD_RUNNING in l_rc:
            log.info("IPMI: Fan control task thread state is running")
            l_state = BMC_CONST.IPMI_FAN_CONTROL_THREAD_RUNNING
        else:
            l_msg = "IPMI: Invalid response from fan control thread state command"
            raise OpTestError(l_msg)
        return l_state

    def ipmi_set_power_limit(self, i_powerlimit):
        '''
        set power limit of bmc

        :param i_powerlimit: power limit to be set at BMC
        :type i_powerlimit: int
        '''
        l_rc = self.ipmitool.run(BMC_CONST.SET_POWER_LIMIT + i_powerlimit)
        if(i_powerlimit not in l_rc):
            raise OpTestError(l_rc)

    def ipmi_get_power_limit(self):
        '''
        Determines the power limit on the bmc

        :returns: current power limit on bmc
        '''
        l_powerlimit = self.ipmitool.run(BMC_CONST.GET_POWER_LIMIT)
        return l_powerlimit

    def ipmi_activate_power_limit(self):
        '''
        Activates the power limit of the target bmc
        '''
        l_rc = self.ipmitool.run(BMC_CONST.DCMI_POWER_ACTIVATE)
        if(BMC_CONST.POWER_ACTIVATE_SUCCESS in l_rc):
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power limit activation failed"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_deactivate_power_limit(self):
        '''
        Deactivates the power limit of the target bmc
        '''
        l_rc = self.ipmitool.run(BMC_CONST.DCMI_POWER_DEACTIVATE)
        if(BMC_CONST.POWER_DEACTIVATE_SUCCESS in l_rc):
            return BMC_CONST.FW_SUCCESS
        else:
            l_msg = "Power limit deactivation failed. " \
                    "Make sure a power limit is set before activating it"
            log.error(l_msg)
            raise OpTestError(l_msg)

    def ipmi_enable_all_occ_sensor(self):
        '''
        Enable OCC Sensor
        '''
        l_status = self.ipmi_get_occ_status()
        # example ssample: OCC Active | 08h | ok  | 210.0 |)

        # Get sensor ids to enable all OCCs
        l_status = l_status.rsplit("\n", 1)[0].split("\n")
        for i in range(len(l_status)):
            l_sensor_id = l_status[i].split("|")[1].strip()[:2]
            self.ipmitool.run(BMC_CONST.BMC_OCC_SENSOR +
                              l_sensor_id + BMC_CONST.BMC_ENABLE_OCC)

        # Wait for OCC to stabilize
        time.sleep(BMC_CONST.OCC_ENABLE_WAIT)
        return BMC_CONST.FW_SUCCESS

    def ipmi_disable_all_occ_sensor(self):
        '''
        Disable OCC Sensor
        '''
        l_status = self.ipmi_get_occ_status()

        # Get sensor ids to disable all OCCs
        l_status = l_status.rsplit("\n", 1)[0].split("\n")
        for i in range(len(l_status)):
            l_sensor_id = l_status[i].split("|")[1].strip()[:2]
            self.ipmitool.run(BMC_CONST.BMC_OCC_SENSOR +
                              l_sensor_id + BMC_CONST.BMC_DISABLE_OCC)

        return BMC_CONST.FW_SUCCESS

    def ipmi_get_occ_status(self):
        '''
        Get OCC status

        example: ::

           OCC 1 Active     | 08h | ok  | 210.0 | Device Enabled
           OCC 2 Active     | 09h | ok  | 210.1 | Device Enabled

        :returns: OCC sensor status or raise OpTestError
        '''
        l_result = self.ipmitool.run(BMC_CONST.OP_CHECK_OCC)
        if ("Device" not in l_result):
            l_msg = "Can't recognize output"
            log.error(l_msg + ": " + l_result)
            raise OpTestError(l_msg)

        return l_result

    def ipmi_get_sel_list(self):
        '''
        This function gets the sel log
        '''
        return self.ipmitool.run(BMC_CONST.BMC_SEL_LIST)

    def ipmi_get_sdr_list(self):
        '''
        This function gets the sdr list
        '''
        return self.ipmitool.run(BMC_CONST.BMC_SDR_ELIST)

    def ipmi_set_pnor_primary_side(self, i_bios_sensor, i_boot_sensor):
        '''
        Sets BIOS sensor and BOOT count to boot pnor from the primary side

        :param i_bios_sensor: Id for BIOS Golden Sensor (example habanero=0x5c)
        :param i_boot_sensor: Id for BOOT Count Sensor (example habanero=80)
        '''
        log.info('\nSetting PNOR to boot into Primary Side')

        # Set the Boot Count sensor to 2
        l_cmd = BMC_CONST.BMC_BOOT_COUNT_2.replace('xx', i_boot_sensor)
        self.ipmitool.run(l_cmd)

        # Set the BIOS Golden Side sensor to 0
        l_cmd = BMC_CONST.BMC_BIOS_GOLDEN_SENSOR_TO_PRIMARY.replace(
            'xx', i_bios_sensor)
        self.ipmitool.run(l_cmd)

        return BMC_CONST.FW_SUCCESS

    def ipmi_set_pnor_golden_side(self, i_bios_sensor, i_boot_sensor):
        '''
        Sets BIOS sensor and BOOT count to boot pnor from the golden side

        :param i_bios_sensor: Id for BIOS Golden Sensor (example habanero=0x5c)
        :param i_boot_sensor: Id for BOOT Count Sensor (example habanero=80)
        '''
        log.info('\nSetting PNOR to boot into Golden Side')

        # Set the Boot Count sensor to 2
        l_cmd = BMC_CONST.BMC_BOOT_COUNT_2.replace('xx', i_boot_sensor)
        self.ipmitool.run(l_cmd)

        # Set the BIOS Golden Side sensor to 1
        l_cmd = BMC_CONST.BMC_BIOS_GOLDEN_SENSOR_TO_GOLDEN.replace(
            'xx', i_bios_sensor)
        self.ipmitool.run(l_cmd)

        return BMC_CONST.FW_SUCCESS

    def ipmi_set_power_policy(self, i_policy):
        '''
        Sets auto-reboot policy with given policy(i_policy)

        :param i_policy: type of policy to be set(chassis policy <i_policy>)

                         - always-off
                         - always-on
                         - previous
        '''
        log.debug("IPMI: Setting the power policy to %s" % i_policy)
        l_cmd = "chassis policy %s" % i_policy
        l_res = self.ipmitool.run(l_cmd)
        log.debug(l_res)

    def ipmi_set_boot_to_petitboot(self):
        '''
        Set boot device to be boot to BIOS (i.e. petitboot)
        '''
        l_output = self.ipmitool.run('chassis bootdev bios')
        if('Set Boot Device to bios' in l_output):
            return 0
        else:
            raise OpTestError(
                "Failure setting bootdev to bios: " + str(l_output))

    def ipmi_set_boot_to_disk(self):
        '''
        Set boot device to be boot to disk (i.e. OS)
        '''
        l_output = self.ipmitool.run('chassis bootdev disk')
        if('Set Boot Device to disk' in l_output):
            return 0
        else:
            raise OpTestError(
                "Failure setting bootdev to disk: " + str(l_output))

    def ipmi_set_no_override(self):
        '''
        Set no boot override so that local config will be effective
        '''
        l_output = self.ipmitool.run('chassis bootdev none')
        if('Set Boot Device to none' in l_output):
            return 0
        else:
            raise OpTestError(
                "Failure setting bootdev to none: " + str(l_output))

    def enter_ipmi_lockdown_mode(self):
        self.ipmitool.run('raw 0x32 0xf3 0x4c 0x4f 0x43 0x4b 0x00')

    def exit_ipmi_lockdown_mode(self):
        self.ipmitool.run('raw 0x32 0xF4 0x55 0x4e 0x4c 0x4f 0x43 0x4b 0x00')

    def last_sel(self):
        return self.ipmitool.run("sel list last 1")

    def sdr_get_watchdog(self):
        return self.ipmitool.run("sdr get \'Watchdog\'")

    def mc_get_watchdog(self):
        return self.ipmitool.run("mc watchdog get")

    def set_tpm_required(self):
        pass

    def clear_tpm_required(self):
        pass

    def is_tpm_enabled(self):
        pass

    def ipmi_get_golden_side_sensor_id(self):
        cmd = "sdr elist -v | grep -i 'BIOS Golden'"
        output = self.ipmitool.run(cmd)
        matchObj = re.search("BIOS Golden Side \((.*)\)", output)
        id = None
        if matchObj:
            id = matchObj.group(1)
        return id

    def ipmi_get_boot_count_sensor_id(self):
        cmd = "sdr elist -v | grep -i 'Boot Count'"
        output = self.ipmitool.run(cmd)
        matchObj = re.search("Boot Count \((.*)\)", output)
        id = None
        if matchObj:
            id = matchObj.group(1)
        return id


class OpTestSMCIPMI(OpTestIPMI):

    def enter_ipmi_lockdown_mode(self):
        self.ipmitool.run('raw 0x3a 0xf3 0x4c 0x4f 0x43 0x4b 0x00')

    def exit_ipmi_lockdown_mode(self):
        self.ipmitool.run('raw 0x3a 0xF4 0x55 0x4e 0x4c 0x4f 0x43 0x4b 0x00')

    def set_tpm_required(self):
        self.ipmitool.run('raw 0x04 0x30 0x49 0x10 0x00 0x02 0 0 0 0 0 0')

    def clear_tpm_required(self):
        self.ipmitool.run('raw 0x04 0x30 0x49 0x10 0x00 0x01 0 0 0 0 0 0')

    def is_tpm_enabled(self):
        res = self.ipmitool.run("sdr elist | grep -i TPM")
        if "State Deasserted" in res:
            log.info("#TPM is disabled")
            return False
        elif "State Asserted" in res:
            log.info("#TPM is enabled")
            return True
