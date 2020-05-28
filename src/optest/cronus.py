#!/usr/bin/env python3
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/common/cronus.py $
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

import os
import datetime
import time
import subprocess
import traceback
import logging
import socket

from .Exceptions import ParameterCheck, UnexpectedCase
from .system import OpSystemState

log = logging.getLogger(__name__)

match_list = ["CRONUS_HOME",
              "OPTKROOT",
              "ECMD_DLL_FILE",
              "ECMD_EXE",
              "ECMD_ARCH",
              "ECMD_TARGET",
              "ECMD_PRODUCT",
              "LD_LIBRARY_PATH",
              "ECMD_PATH",
              "ECMD_PLUGIN",
              "ECMD_RELEASE",
              "ECMDPERLBIN",
              "PERL5LIB",
              "PYTHONPATH",
              "PATH",
              "LABCPU",
              "LABTS",
              "SBE_TOOLS_PATH",
              ]


class cronus():
    '''
    Class for managing a cronus shell session.

    See testcases/testCronus.py for Cronus Install and Setup
    '''

    def __init__(self, conf):
        self.conf = conf
        self.env_ready = False  # too early to know if system supports cronus
        self.cronus_ready = False  # flag to indicate setup complete
        self.cv_SYSTEM = None  # flag to show if we have a system yet
        self.capable = False
        self.current_target = None
        self.cronus_env = None

#        cronusgroup = parser.add_argument_group("Cronus", "Cronus Config options")
#        cronusgroup.add_argument( "--cronus-release", default="auto", help="cronus release")
#        cronusgroup.add_argument( "--cronus-product", default="p9", help="cronus product")
#        cronusgroup.add_argument("--cronus-system-type", default="witherspoon", help="cronus system type")
#        cronusgroup.add_argument("--cronus-code-level", default="dev", help="cronus code level")
#        cronusgroup.add_argument("--cronus-hdct", default="/opt/openpower/p9/crondump/hdct_p9", help="cronus hardware dump content table file")
#        cronusgroup.add_argument("--cronus-hdct", default="hdct.txt", help="cronus hardware dump content table file")
#        cronusgroup.add_argument("--cronus-dump-directory", default=none, help="cronus dump file directory")
#        cronusgroup.add_argument("--cronus-dump-suffix", default="optest", help="cronus dump file suffix")
#        cronusgroup.add_argument("--cronus-smart-path", action='store_true', default=false, help="cronus path added after /usr/bin")

    def dump_env(self):
        for xs in sorted(match_list):
            log.debug("os.environ[{}]={}".format(xs, os.environ[xs]))

    def setup(self):
        self.cv_SYSTEM = self.conf.system()  # we hope its not still too early
        # test no op_system
        self.capable = self.cv_SYSTEM.cronus_capable()
        if not self.cv_SYSTEM.cronus_capable():
            log.debug("System is NOT cronus_capable={}".format(
                self.cv_SYSTEM.cronus_capable()))
            # safeguards
            self.env_ready = False
            self.cronus_ready = False
            return
        # rc=139 is a segfault (-11)
        log.debug("gethostbyname starts '{}'".format(self.conf.args.bmc_ip))
        just_ip = socket.gethostbyname(self.conf.args.bmc_ip)
        log.debug("gethostbyname ends '{}'".format(just_ip))
        proposed_target = just_ip + "_optest_target"
        ecmdtargetsetup_string = ("ecmdtargetsetup -n \"{}\" "
                                  "-env hw -sc \"k0:eth:{}\" "
                                  "-bmc \"k0:eth:{}\" "
                                  "-bmcid \"k0:{}\" "
                                  "-bmcpw \"k0:{}\""
                                  .format(proposed_target,
                                          just_ip,
                                          just_ip,
                                          self.conf.args.bmc_username,
                                          self.conf.args.bmc_password))
        try:
            op_cronus_login = "/etc/profile.d/openpower.sh"
            self.cronus_env = os.path.join(self.conf.logdir, "cronus.env")
            if not os.path.isfile(op_cronus_login):
                log.warning("NO Cronus installed, check the system")
                return
        except Exception as e:
            log.warning("Cronus setup problem check the installation,"
                        " Exception={}".format(e))
        try:
            source_string = ("source {} && "
                             "ecmdsetup auto cro {} {} && "
                             "printenv >{}"
                             .format(op_cronus_login,
                                     self.conf.args.cronus_product,
                                     self.conf.args.cronus_code_level,
                                     self.cronus_env))
            command = "source"
            stdout_value = self.conf.util.cronus_subcommand(
                command=source_string, minutes=2)
            log.debug("source stdout='{}'".format(stdout_value))

            if not os.path.isfile(self.cronus_env):
                log.error("NO Cronus environment "
                          "data captured, this is a problem")
                raise UnexpectedCase(message="NO Cronus environment "
                                     "data captured, this is a problem")
            ecmd_dict = {}
            with open(self.cronus_env) as f:
                for line in f:
                    new_line = line.split("=")
                    for xs in match_list:
                        if xs == new_line[0]:
                            if len(new_line) >= 2:
                                ecmd_dict[new_line[0]] = new_line[1].rstrip()
            log.debug("ECMD's len(match_list)={} len(ecmd_dict)={}, "
                      "these may not match"
                      .format(len(match_list), len(ecmd_dict)))
            for k, v in sorted(ecmd_dict.items()):
                log.debug("ecmd_dict[{}]={}".format(k, ecmd_dict[k]))
                os.environ[k] = ecmd_dict[k]

            self.env_ready = True
            log.debug(
                "cronus setup setting self.env_ready={}".format(self.env_ready))

        except subprocess.CalledProcessError as e:
            tb = traceback.format_exc()
            raise UnexpectedCase(message="Cronus environment issue rc={} "
                                 "output={} traceback={}"
                                 .format(e.returncode, e.output, tb))
        except Exception as e:
            tb = traceback.format_exc()
            raise UnexpectedCase(message="Cronus environment issue "
                                 "Exception={} traceback={}"
                                 .format(e, tb))

        try:
            command = "ecmdtargetsetup"
            stdout_value = self.conf.util.cronus_subcommand(
                command=ecmdtargetsetup_string, minutes=2)
            log.debug("ecmdtargetsetup stdout='{}'".format(stdout_value))

            target_string = "target {}".format(proposed_target)
            command = "target"
            stdout_value = self.conf.util.cronus_subcommand(
                command=target_string, minutes=2)
            log.debug("target stdout='{}'".format(stdout_value))

            self.current_target = proposed_target
            log.debug("ECMD_TARGET={}".format(self.current_target))
            # need to manually update the environment to persist
            os.environ['ECMD_TARGET'] = self.current_target

            command = "setupsp"
            stdout_value = self.conf.util.cronus_subcommand(
                command=command, minutes=2)
            log.debug("target stdout='{}'".format(stdout_value))

            if self.cv_SYSTEM.get_state() not in [OpSystemState.OFF]:
                command = "crodetcnfg"
                crodetcnfg_string = ("crodetcnfg {}"
                                     .format(self.conf.args.cronus_system_type))
                stdout_value = self.conf.util.cronus_subcommand(
                    command=crodetcnfg_string, minutes=2)
                log.debug("crodetcnfg stdout='{}'".format(stdout_value))
                self.cronus_ready = True
                log.debug("cronus_ready={}".format(self.cronus_ready))
            else:
                log.warning("Cronus problem setting up, we need the "
                            "System powered ON and it is OFF")
                raise UnexpectedCase(state=self.cv_SYSTEM.get_state(),
                                     message=("Cronus setup problem, we need"
                                              " the System powered ON and it is OFF"))
        except subprocess.CalledProcessError as e:
            tb = traceback.format_exc()
            raise UnexpectedCase(message="Cronus setup issue rc={} output={}"
                                 " traceback={}"
                                 .format(e.returncode, e.output, tb))
        except Exception as e:
            tb = traceback.format_exc()
            raise UnexpectedCase(message="Cronus setup issue Exception={}"
                                 " traceback={}".format(e, tb))

    def cronus_subcommand(self, command=None, minutes=2):
        # cronus class calls this, so be cautious on recursive calls
        assert 0 < minutes <= 120, (
            "cronus_subcommand minutes='{}' is out of the desired range of 1-120"
            .format(minutes))
        completed = False
        try:
            p1 = subprocess.Popen(["bash", "-c", command],
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  universal_newlines=True,
                                  encoding='utf-8')
            # set the polling appropriate
            if minutes > 5:
                sleep_period = 60
                custom_range = minutes
            else:
                sleep_period = 1
                custom_range = minutes*60
            log.debug("cronus_subcommand sleep_period seconds='{}' number of periods to wait (custom_range)='{}'\n"
                      " Waiting for minutes='{}' which is seconds='{}')"
                      .format(sleep_period, custom_range, minutes, minutes*60))
            for t in range(custom_range):
                log.debug("polling t={}".format(t))
                time.sleep(sleep_period)
                if p1.poll() is not None:
                    log.debug("polling completed=True")
                    completed = True
                    break
            if not completed:
                log.warning("cronus_subcommand did NOT complete in '{}' minutes, rc={}".format(
                    minutes, p1.returncode))
                p1.kill()
                log.warning(
                    "cronus_subcommand killed command='{}'".format(command))
                raise UnexpectedCase(
                    message="Cronus issue rc={}".format(p1.returncode))
            else:
                log.debug("cronus_subcommand rc={}".format(p1.returncode))
                stdout_value, stderr_value = p1.communicate()
                log.debug("command='{}' p1.returncode={}"
                          .format(command, p1.returncode))
                if p1.returncode:
                    log.warning("RC={} cronus_subcommand='{}', debug log contains stdout/stderr"
                                .format(p1.returncode, command))
                log.debug("cronus_subcommand command='{}' stdout='{}' stderr='{}'"
                          .format(command, stdout_value, stderr_value))
                if stderr_value:
                    # some calls get stderr which is noise
                    log.debug("Unknown if this is a problem, Command '{}' stderr='{}'".format(
                        command, stderr_value))
                return stdout_value
        except subprocess.CalledProcessError as e:
            tb = traceback.format_exc()
            log.debug(
                "cronus_subcommand issue CalledProcessError={}, Traceback={}".format(e, tb))
            raise UnexpectedCase(
                message="Cronus issue rc={} output={}".format(e.returncode, e.output))
        except Exception as e:
            tb = traceback.format_exc()
            log.debug(
                "cronus_subcommand issue Exception={}, Traceback={}".format(e, tb))
            raise UnexpectedCase(
                message="cronus_subcommand issue Exception={}, Traceback={}".format(e, tb))

    def cronus_run_command(self, command=None, minutes=2):
        # callers should assure its not too early in system life to call
        # we need a system object, configuration.py env_ready cronus_ready
        assert 0 < minutes <= 120, (
            "cronus_run_command minutes='{}' is out of the desired range of 1-120"
            .format(minutes))
        log.debug("env_ready={} cronus_ready={}"
                  .format(self.conf.cronus.env_ready, self.conf.cronus.cronus_ready))
        if not self.conf.cronus.env_ready or not self.conf.cronus.cronus_ready:
            log.debug("Cronus not ready, calling setup")
            self.conf.cronus.setup()
            if not self.conf.cronus.env_ready or not self.conf.cronus.cronus_ready:
                log.warning("We tried to setup Cronus, either Cronus is not installed"
                            " on your op-test box or target system is NOT supported yet"
                            " (only OpenBMC so far), "
                            "or some other system problem, checking further")
                if self.conf.cronus.cv_SYSTEM is not None:
                    cronus_state = self.conf.cronus.cv_SYSTEM.get_state()
                    log.warning("cronus_state={} capable={}"
                                .format(cronus_state, self.conf.cronus.capable))
                    raise UnexpectedCase(state=cronus_state,
                                         message="We tried to setup Cronus and something is "
                                         "not working, check the debug log")
                else:
                    log.warning("We do not have a system object yet, it "
                                "may be too early to call cronus_run_command")
                    raise UnexpectedCase(message="We do not have a system "
                                         "object yet, it may be too early to call cronus_run_command")

        if not command:
            log.warning("cronus_run_command requires a command to run")
            raise ParameterCheck(
                message="cronus_run_command requires a command to run")
        self.conf.cronus.dump_env()
        log.debug("cronus_run_command='{}' target='{}'"
                  .format(command, self.conf.cronus.current_target))
        stdout_value = self.cronus_subcommand(command=command, minutes=minutes)
        return stdout_value
