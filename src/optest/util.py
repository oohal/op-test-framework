#!/usr/bin/env python3
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/common/OpTestUtil.py $
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

import subprocess
import traceback
import datetime
import string
import random
import time
import pwd
import sys
import os
import re


import telnetlib
import requests
import pexpect
import urllib3  # setUpChildLogger enables integrated logging with op-test
import json

from requests.adapters import HTTPAdapter
#from requests.packages.urllib3.util import Retry
from http.client import HTTPConnection
# HTTPConnection.debuglevel = 1 # this will print some additional info to stdout

from .constants import Constants as BMC_CONST
from .exceptions import CommandFailed, RecoverFailed, ConsoleSettings, OpTestError
from .exceptions import HostLocker, AES, ParameterCheck, HTTPCheck, UnexpectedCase

import logging
from . import OpTestLogger
log = OpTestLogger.optest_logger_glob.get_logger(__name__)

class OpTestUtil():

    def __init__(self, conf=None):
        self.conf = conf

    def setup(self, config='HostLocker'):
        # we need this called AFTER the proper configuration values have been seeded
        if config == 'AES':
            self.conf.util_server = Server(url=self.conf.args.aes_server,
                                           base_url=self.conf.args.aes_base_url,
                                           minutes=None,
                                           proxy=self.build_proxy(self.conf.args.aes_proxy,
                                                                  self.conf.args.aes_no_proxy_ips))
        elif config == 'REST':
            rest_server = "https://{}".format(self.conf.args.bmc_ip)
            self.conf.util_bmc_server = Server(url=rest_server,
                                               username=self.conf.args.bmc_username,
                                               password=self.conf.args.bmc_password)
        else:
            self.conf.util_server = Server(url=self.conf.args.hostlocker_server,
                                           base_url=self.conf.args.hostlocker_base_url,
                                           minutes=None,
                                           proxy=self.build_proxy(self.conf.args.hostlocker_proxy,
                                                                  self.conf.args.hostlocker_no_proxy_ips))

    def check_lockers(self):
        if self.conf.args.hostlocker is not None:
            self.conf.util.hostlocker_lock(self.conf.args)

        if self.conf.args.aes is not None:
            query = False
            lock = False
            unlock = False
            for i in range(len(self.conf.args.aes)):
                if self.conf.args.aes[i].lower() == 'q':
                    query = True
                    # remove the q flag in case env name is also q
                    del self.conf.args.aes[i]
                    break
                if self.conf.args.aes[i].lower() == 'l':
                    lock = True
                    # remove the l flag in case env name is also l
                    del self.conf.args.aes[i]
                    break
                if self.conf.args.aes[i].lower() == 'u':
                    unlock = True
                    # remove the u flag in case env name is also u
                    del self.conf.args.aes[i]
                    break

            # removes any duplicates
            self.conf.args.aes = list(set(self.conf.args.aes))

            if query:
                envs, search_criteria = self.conf.util.aes_get_environments(
                    self.conf.args)
                if envs is not None:
                    self.conf.util.aes_print_environments(envs)
                else:
                    print(("NO environments found, (if Environment_Name added its "
                           "probably a syntax problem with --aes q, look at "
                           "--aes-search-args), we used --aes-search-args {}\n"
                           .format(' '.join(search_criteria))))
                self.conf.util.cleanup()
                exit(0)
            if lock:
                envs, search_criteria = self.conf.util.aes_get_environments(
                    self.conf.args)
                if envs is not None and len(envs) > 0:
                    if len(envs) <= 1:
                        for env in envs:
                            # working_id should NOT be kept to release upon exit
                            working_id = self.conf.util.aes_lock_env(env=env)
                            if working_id is None:
                                print(("AES shows NOT available to LOCK, "
                                       "Environment_EnvId={} Environment_Name='{}' "
                                       "Environment_State={} res_id={} res_email={}"
                                       .format(env['env_id'], env['name'], env['state'],
                                               env['res_id'], env['res_email'])))
                            else:
                                print(("AES LOCKED Environment_EnvId={} "
                                       "Environment_Name='{}' res_id={} aes-add-locktime "
                                       "(in hours, zero is Never Expires) = '{}'"
                                       .format(env['env_id'], env['name'], working_id,
                                               self.conf.args.aes_add_locktime)))
                    else:
                        print(("AES LOCK limit imposed, we found {} environments "
                               "using --aes-search-args {} and we must find only "
                               "one to lock here, use --aes q with your "
                               "--aes-search-args to view what we found"
                               .format(len(envs), ' '.join(search_criteria))))
                else:
                    print(("Found NO environments using --aes-search-args {}, "
                           "use --aes q with your --aes-search-args to view "
                           "what we found".format(' '.join(search_criteria))))
                self.conf.util.cleanup()
                exit(0)  # exit lock branch
            if unlock:
                envs, search_criteria = self.conf.util.aes_get_environments(
                    self.conf.args)
                if envs is not None:
                    if len(envs) <= 1:
                        for env in envs:
                            res_id = self.conf.util.aes_release_reservation(
                                env=env)
                            if res_id is None:
                                print(("AES shows NO LOCK, so skipped UNLOCK "
                                       "Environment_EnvId={} Environment_Name='{}' "
                                       "Environment_State={} res_id={} res_email={}"
                                       .format(env['env_id'], env['name'], env['state'],
                                               env['res_id'], env['res_email'])))
                            else:
                                print(("AES UNLOCKed Environment_EnvId={} "
                                       "Environment_Name='{}' res_id={} res_email={}"
                                       .format(env['env_id'], env['name'],
                                               env['res_id'], env['res_email'])))
                    else:
                        print(("AES UNLOCK limit imposed, we found {} "
                               "environments and we must only find one to unlock "
                               "here, use --aes-search-args to limit "
                               "serach criteria".format(len(envs))))
                else:
                    print(("NO AES environments found using --aes-search-args {}"
                           .format(' '.join(search_criteria))))
                self.conf.util.cleanup()
                exit(0)  # exit unlock branch
            else:  # we filtered out all else so now find an env and lock it
                self.conf.lock_dict = self.conf.util.aes_lock(self.conf.args,
                                                              self.conf.lock_dict)
                environments = self.conf.lock_dict.get('envs')
                if self.conf.lock_dict.get('res_id') is None:
                    if self.conf.aes_print_helpers is True:
                        self.conf.util.aes_print_environments(environments)
                    # MESSAGE 'unable to lock' must be kept in same line to be filtered
                    raise AES(message="OpTestSystem AES unable to lock environment "
                              "requested, try --aes q with options for --aes-search-args "
                              "to view availability")
                else:
                    log.info("OpTestSystem AES Reservation for Environment_Name '{}' "
                             "Group_Name={} Reservation id={}"
                             .format(self.conf.lock_dict.get('name'),
                                     self.conf.lock_dict.get('Group_Name'),
                                     self.conf.lock_dict.get('res_id')))
        elif self.conf.args.aes_search_args is not None:
            self.conf.lock_dict = self.conf.util.aes_lock(self.conf.args,
                                                          self.conf.lock_dict)
            environments = self.conf.lock_dict.get('envs')
            if self.conf.lock_dict.get('res_id') is None:
                if self.conf.aes_print_helpers is True:
                    self.conf.util.aes_print_environments(environments)
                # MESSAGE 'unable to lock' must be kept in same line to be filtered
                raise AES(message="OpTestSystem AES NO available environments matching "
                          "criteria (see output earlier), unable to lock,"
                          "try running op-test with --aes q "
                          "--aes-search-args Environment_State=A "
                          "to query system availability, if trying to use "
                          "existing reservation the query must be exactly one")
            else:
                log.info("OpTestSystem AES Reservation for Environment_Name '{}' "
                         "Group_Name={} Reservation id={}"
                         .format(self.conf.lock_dict.get('name'),
                                 self.conf.lock_dict.get('Group_Name'),
                                 self.conf.lock_dict.get('res_id')))

    def cleanup(self):
        if self.conf.args.hostlocker is not None:
            if self.conf.args.hostlocker_keep_lock is False:
                try:
                    self.hostlocker_unlock()
                except Exception as e:
                    log.warning("OpTestSystem HostLocker attempted to release "
                                "host '{}' hostlocker-user '{}', please manually "
                                "verify and release".format(self.conf.args.hostlocker,
                                                            self.conf.args.hostlocker_user))
                rc, lockers = self.hostlocker_locked()
                if rc == 0:
                    # there can be cases during signal handler cleanup
                    # where we get interrupted before the actual lock hit
                    # so this message can be output even though no lock was
                    # actually released, no two phase commits here :0
                    # other cases exist where we confirm no locks held, but
                    # the info message may say released, due to exceptions thrown
                    insert_message = ", host is locked by '{}'".format(lockers)
                    if len(lockers) == 0:
                        insert_message = ""
                    log.info("OpTestSystem HostLocker cleanup for host '{}' "
                             "hostlocker-user '{}' confirms you do not hold the lock{}"
                             .format(self.conf.args.hostlocker,
                                     self.conf.args.hostlocker_user, insert_message))
                else:  # we only care if user held the lock
                    log.warning("OpTestSystem HostLocker attempted to cleanup "
                                "and release the host '{}' and we were unable to verify, "
                                "please manually verify and release"
                                .format(self.conf.args.hostlocker))
        # clear since signal handler may call and exit path
        self.conf.args.hostlocker = None

        if self.conf.args.aes is not None or self.conf.args.aes_search_args is not None:
            if self.conf.args.aes_keep_lock is False:
                if self.conf.lock_dict.get('res_id') is not None:
                    temp_res_id = self.aes_release_reservation(
                        res_id=self.conf.lock_dict.get('res_id'))
                    if temp_res_id is not None:
                        log.info("OpTestSystem AES releasing reservation {} "
                                 "Environment_Name '{}' Group_Name {}"
                                 .format(self.conf.lock_dict.get('res_id'),
                                         self.conf.lock_dict.get('name'),
                                         self.conf.lock_dict.get('Group_Name')))
                        # clear signal handler may call and exit path
                        self.conf.lock_dict['res_id'] = None
                    else:
                        log.info("OpTestSystem AES attempted to cleanup and release "
                                 "reservation {} Environment_Name '{}' Group_Name {}"
                                 " and we were unable to verify, please manually verify "
                                 "and release".format(self.conf.lock_dict.get('res_id'),
                                                      self.conf.lock_dict.get(
                                                          'name'),
                                                      self.conf.lock_dict.get('Group_Name')))

        if self.conf.util_server is not None:
            # AES and Hostlocker skip logout
            log.debug("Closing util_server")
            self.conf.util_server.close()

        if self.conf.util_bmc_server is not None:
            log.debug("Logging out of util_bmc_server")
            self.conf.util_bmc_server.logout()
            log.debug("Closing util_bmc_server")
            self.conf.util_bmc_server.close()

        if self.conf.dump:
            self.conf.dump = False # possible for multiple passes here
            # currently only pulling OpenBMC logs
            marker_time = (time.asctime(time.localtime())).replace(" ", "_")
            if self.conf.args.bmc_type in ['OpenBMC']:
                try:
                    ping_mtu_check(self.conf.args.bmc_ip, totalSleepTime=BMC_CONST.PING_RETRY_FOR_STABILITY)
                except Exception as e:
                    log.warning("Check that the BMC is healthy, maybe the Broadcom bug, Exception={}".format(e))
                log.info("OpTestSystem Starting to Gather BMC logs")
                try:
                    journal_dmesg_outfile = "op-test-openbmc-journal-dmesg.{}".format(marker_time)
                    journal_dmesg_entries = self.conf.bmc().run_command("journalctl -k --no-pager >/tmp/{}".format(journal_dmesg_outfile))
                    journal_outfile = "op-test-openbmc-journal.{}".format(marker_time)
                    journal_entries = self.conf.bmc().run_command("journalctl --no-pager >/tmp/{}".format(journal_outfile))
                    top_outfile = "op-test-openbmc-top.{}".format(marker_time)
                    top_entries = self.conf.bmc().run_command("top -b -n 1 >/tmp/{}".format(top_outfile))
                    df_outfile = "op-test-openbmc-df.{}".format(marker_time)
                    df_entries = self.conf.bmc().run_command("df -h >/tmp/{}".format(df_outfile))
                    uptime_outfile = "op-test-openbmc-uptime.{}".format(marker_time)
                    uptime_entries = self.conf.bmc().run_command("uptime >/tmp/{}".format(uptime_outfile))
                    console_outfile = "op-test-openbmc-console-log.{}".format(marker_time)
                    # obmc-console.log will exist even if empty
                    console_entries = self.conf.bmc().run_command("cp /var/log/obmc-console.log /tmp/{}"
                                          .format(console_outfile))
                    copyFilesFromDest(self.conf.args.bmc_username,
                        self.conf.args.bmc_ip,
                        "/tmp/op-test*",
                        self.conf.args.bmc_password,
                        self.conf.logdir)
                except Exception as e:
                    log.debug("OpTestSystem encountered a problem trying to gather the BMC logs, Exception={}".format(e))
                # remove temp files
                try:
                    self.conf.bmc().run_command("rm /tmp/op-test*")
                except Exception as e:
                    log.warning("OpTestSystem encountered a problem cleaning up BMC /tmp files, you may want to check.")
                log.info("OpTestSystem Completed Gathering BMC logs, find them in the Log Location")
            # this will get esels for all
            log.info("OpTestSystem Starting to Gather ESEL's")
            try:
                esel_entries = self.conf.op_system.sys_sel_elist()
                esel_outfile = "{}/op-test-esel.{}".format(self.conf.logdir, marker_time)
                self.dump_list(entries=esel_entries, outfile=esel_outfile)
                log.info("OpTestSystem Completed Gathering ESEL's, find them in the Log Location")
            except Exception as e:
                log.debug("OpTestSystem encountered a problem trying to gather ESEL's, Exception={}".format(e))
            self.dump_versions()
            self.dump_nvram_opts()

        # leave closing the qemu scratch disk until last
        # no known reasons at this point, document in future
        try:
            log.debug("self.conf.args.qemu_scratch_disk={}"
                      .format(self.conf.args.qemu_scratch_disk))
            if self.conf.args.qemu_scratch_disk is not None:
                self.conf.args.qemu_scratch_disk.close()
                log.debug("Successfully closed qemu_scratch_disk")
                self.conf.args.qemu_scratch_disk = None  # in case we pass here again
        except Exception as e:
            log.debug("self.conf.args.qemu_scratch_disk={} "
                      "closing Exception={}"
                      .format(self.conf.args.qemu_scratch_disk, e))

    def dump_list(self, entries=None, outfile=None):
        '''
        Purpose of this function is to dump a list object to the
        file system to be used by other methods, etc.
        '''
        if entries is None or outfile is None:
            raise ParameterCheck(message="Check your call to dump_list, entries"
                                     " and outfile need valid values")
        if type(entries) == str:
            list_obj = entries.splitlines()
        else:
            list_obj = entries
        list_obj.insert(0, "From BMC {} Host {}".format(self.conf.args.bmc_ip, self.conf.args.host_ip))
        with open(outfile, 'w') as f:
            for line in list_obj:
                f.write("{}\n".format(line))

    def dump_versions(self):
        log.info("Log Location: {}/*debug*".format(self.conf.output))
        log.info("\n----------------------------------------------------------\n"
                 "OpTestSystem Firmware Versions Tested\n"
                 "(if flashed things like skiboot.lid, may not be accurate)\n"
                 "----------------------------------------------------------\n"
                 "{}\n"
                 "----------------------------------------------------------\n"
                 "----------------------------------------------------------\n"
                 .format(
                     (None if self.conf.firmware_versions is None
                      else ('\n'.join(f for f in self.conf.firmware_versions)))
                 ))

    def check_nvram_options(self, console):
        try:
            console.run_command("which nvram")
        except:
            log.info("No NVRAM utility available to check options")
            return

        try:
            result = console.run_command("nvram -p ibm,skiboot --print-config")
        except CommandFailed as cf:
            if 'There is no Open Firmware "ibm,skiboot" partition!' in ''.join(cf.output):
                result = []
                pass
            else:
                raise cf

        self.conf.nvram_debug_opts = [o for o in result if "=" in o]

        if len(self.conf.nvram_debug_opts) == 0:
            log.info("No NVRAM debugging options set")
            return

        log.warning("{} NVRAM debugging options set".format(
            len(self.conf.nvram_debug_opts)))

    def dump_nvram_opts(self):
        if self.conf.nvram_debug_opts is None or len(self.conf.nvram_debug_opts) == 0:
            return

        log.warning("\n{} NVRAM debugging options set\n"
                    "These may adversely affect test results; verify these are appropriate if a failure occurs:\n"
                    "----------------------------------------------------------\n"
                    "{}\n"
                    "----------------------------------------------------------\n"
                    .format(len(self.conf.nvram_debug_opts), '\n'.join(f for f in self.conf.nvram_debug_opts)))

    def build_proxy(self, proxy, no_proxy_ips):
        if no_proxy_ips is None:
            return proxy

        for ip in no_proxy_ips:
            cmd = 'ip addr show to %s' % ip
            try:
                output = subprocess.check_output(cmd.split())
            except (subprocess.CalledProcessError, OSError) as e:
                raise HostLocker(
                    message="Could not run 'ip' to check for no proxy?")

            if len(output):
                proxy = None
                break

        return proxy

    def get_env_name(self, x):
        return x['name']

    def aes_print_environments(self, environments):
        if environments is None:
            return
        sorted_env_list = sorted(environments, key=self.get_env_name)
        print("--------------------------------------------------------------------------------")
        for env in sorted_env_list:
            print(("--aes-search-args Environment_Name='{}' Environment_EnvId={} "
                   "Group_Name='{}' Group_GroupId={} Environment_State={} <res_id={} "
                   "res_email={} aes-add-locktime={}>"
                   .format(env['name'], env['env_id'], env['group']['name'],
                           env['group']['group_id'], env['state'], env['res_id'],
                           env['res_email'], env['res_length'], )))
        print("--------------------------------------------------------------------------------")
        print("\nHELPERS   --aes-search-args Server_VersionName=witherspoon|boston|habanero|zz|tuleta"
              "|palmetto|brazos|fleetwood|p8dtu|p9dsu|zaius|stratton|firestone|garrison|romulus|alpine")
        print("          --aes-search-args Server_HardwarePlatform=POWER8|POWER9|openpower")
        print("          --aes-search-args Group_Name=op-test")
        print("          --aes-search-args Environment_State=A|R|M|X|H|E")
        print("A=Available R=Reserved M=Maintenance X=Offline H=HealthCheck E=Exclusive")
        print(("AES Environments found = {}".format(len(sorted_env_list))))

    def aes_release_reservation(self, res_id=None, env=None):
        release_dict = {'result': None,
                        'status': None,
                        'message': None,
                        }
        if res_id is None:
            if env is not None:
                res_id = env.get('res_id')
        if res_id is None:
            return None  # nothing to do
        res_payload = {'res_id': res_id}
        uri = "/release-reservation.php"
        try:
            r = self.conf.util_server.get(uri=uri, params=res_payload)
            if r.status_code != requests.codes.ok:
                raise AES(message="OpTestSystem AES attempted to release "
                          "reservation '{}' but it was NOT found in AES, "
                          "please update and retry".format(res_id))
        except Exception as e:
            raise AES(message="OpTestSystem AES attempted to releasing "
                      "reservation '{}' but encountered an Exception='{}', "
                      "please manually verify and release".format(res_id, e))

        try:
            json_data = r.json()
            release_dict['status'] = json_data.get('status')
            release_dict['result'] = json_data.get('result')
            if json_data.get('result').get('res_id') != res_id:
                log.warning("OpTestSystem AES UNABLE to confirm the release "
                            "of the reservation '{}' in AES, please manually "
                            "verify and release if needed, see details: {}"
                            .format(res_id, release_dict))
        except Exception as e:
            # this seems to be the typical path from AES, not sure what's up
            log.debug(
                "NO JSON object from aes_release_reservation, r.text={}".format(r.text))
            release_dict['message'] = r.text
            log.debug("OpTestSystem AES UNABLE to confirm the release "
                      "of the reservation '{}' in AES, please manually "
                      "verify and release if needed, see details: {}"
                      .format(res_id, release_dict))

        return res_id

    def aes_get_environments(self, args):
        # this method initializes the Server request session
        get_dict = {'result': None,
                    'status': None,
                    'message': None,
                    }
        args_dict = vars(args)
        if self.conf.util_server is None:
            self.setup(config='AES')
        if self.conf.args.aes_search_args is None:
            self.conf.args.aes_search_args = []
            if self.conf.args.aes is not None:
                for i in range(len(self.conf.args.aes)):
                    # add the single env to the list of search
                    self.conf.args.aes_search_args += ("Environment_Name={}"
                                                       .format(self.conf.args.aes[i]).splitlines())
            else:
                return None, None  # we should NOT have gotten here
        else:
            if self.conf.args.aes is not None:
                for i in range(len(self.conf.args.aes)):
                    self.conf.args.aes_search_args += ("Environment_Name={}"
                                                       .format(self.conf.args.aes[i]).splitlines())

        uri = "/get-environments.php"
        payload = {'query_params[]': self.conf.args.aes_search_args}
        r = self.conf.util_server.get(uri=uri, params=payload)

        if r.status_code != requests.codes.ok:
            raise AES(message="OpTestSystem AES UNABLE to find the environment '{}' "
                      "in AES, please update and retry".format(self.conf.args.aes))

        # SQL issues can cause various problems which come back as ok=200
        filter_list = ["have an error"]
        matching = [xs for xs in filter_list if xs in r.text]
        if len(matching):
            raise AES(message="OpTestSystem AES encountered an error,"
                      " check the syntax of your query and retry, Exception={}"
                      .format(r.text))

        # we need this here to set the aes_user for subsequent calls
        if self.conf.args.aes_user is None:
            self.conf.args.aes_user = pwd.getpwuid(os.getuid()).pw_name

        aes_response_json = r.json()

        get_dict['status'] = aes_response_json.get('status')
        if aes_response_json.get('status') == 0:
            get_dict['result'] = aes_response_json.get('result')
        else:
            get_dict['message'] = aes_response_json.get('message')
            raise AES(message="Something unexpected happened, "
                      "see details: {}".format(get_dict))

        return get_dict.get('result'), self.conf.args.aes_search_args

    def aes_get_env(self, env):
        uri = "/get-environment-info.php"
        env_payload = {'env_id': env['env_id']}
        r = self.conf.util_server.get(uri=uri, params=env_payload)
        if r.status_code != requests.codes.ok:
            raise AES(message="OpTestSystem AES UNABLE to find the environment '{}' "
                      "in AES, please update and retry".format(env['env_id']))

        aes_response_json = r.json()

        if aes_response_json.get('status') == 0:
            return aes_response_json['result'][0]

    def aes_add_time(self, env=None, locktime=24):
        # Sept 10, 2018 - seems to be some issue with add-res-time.php
        # even in Web UI the Add an Hour is not working
        # locktime number of hours to add
        # if aes_add_time called when AES reservation is
        # in expiration window this fails
        # not sure how that calculation is done yet
        time_dict = {'result': None,
                     'status': None,
                     'message': None,
                     }
        if locktime == 0:
            # if default, add some time
            # allows user to specify command line override
            locktime = 24
        uri = "/add-res-time.php"
        res_payload = {'res_id': env.get('res_id'),
                       'hours': float(locktime),
                       }
        r = self.conf.util_server.get(uri=uri, params=res_payload)
        if r.status_code != requests.codes.ok:
            raise AES(message="OpTestSystem AES UNABLE to find the reservation "
                      "res_id '{}' in AES, please update and retry".format(env['res_id']))

        aes_response_json = r.json()

        time_dict['status'] = aes_response_json.get('status')
        if aes_response_json.get('status') == 0:
            time_dict['result'] = aes_response_json.get('result')
        else:
            time_dict['message'] = aes_response_json.get('message')
            raise AES(message="OpTestSystem AES UNABLE to add time to existing "
                      "reservation, the reservation may be about to expire or "
                      "conflict exists, see details: {}".format(time_dict))
        return time_dict

    def aes_get_creds(self, env, args):
        # version_mappings used for bmc_type
        #                        AES             op-test
        version_mappings = {'witherspoon': 'OpenBMC',
                            'zaius': 'OpenBMC',
                            'boston': 'SMC',
                            'stratton': 'SMC',
                            'p9dsu': 'SMC',
                            'p8dtu': 'SMC',
                            'firestone': 'AMI',
                            'garrison': 'AMI',
                            'habanero': 'AMI',
                            'palmetto': 'AMI',
                            'romulus': 'AMI',
                            'alpine': 'FSP',
                            'brazos': 'FSP',
                            'fleetwood': 'FSP',
                            'tuleta': 'FSP',
                            'zz': 'FSP',
                            'unknown': 'unknown',
                            'qemu': 'qemu',
                            }

        # aes_mappings used for configuration parameters
        #                        AES             op-test
        aes_mappings = {'os_password': 'host_password',
                        'os_username': 'host_user',
                        'os_host': 'host_ip',
                        'net_mask': 'host_submask',
                        'os_mac_address': 'host_mac',
                        'def_gateway': 'host_gateway',
                        'mac_address': 'bmc_mac',
                        'password': 'bmc_password',
                        'username': 'bmc_username',
                        'host_name': 'bmc_ip',
                        'ipmi_username': 'bmc_usernameipmi',
                        'ipmi_password': 'bmc_passwordipmi',
                        'version_name': 'bmc_type',
                        'hardware_platform': 'platform',
                        'attached_disk': 'host_scratch_disk',
                        }

        args_dict = vars(args)  # we store credentials to the args
        if len(env['servers']) != 1:
            # we may not yet have output a message about reservation
            # but we will get the release message
            self.cleanup()
            raise AES(message="AES credential problem, check AES definitions "
                      "for server record, we either have no server record or more "
                      "than one, check FSPs and BMCs")

        for key, value in list(aes_mappings.items()):
            if env['servers'][0].get(key) is not None and env['servers'][0].get(key) != '':
                if key == 'version_name':
                    args_dict[aes_mappings[key]] = version_mappings.get(
                        env['servers'][0][key].lower())
                else:
                    args_dict[aes_mappings[key]] = env['servers'][0][key]

    def aes_lock_env(self, env=None):
        if env is None:
            return
        new_res_id = None
        res_payload = {'email': self.conf.args.aes_user,
                       'query_params[]': None,
                       'needs_claim': False,
                       'length': float(self.conf.args.aes_add_locktime),
                       'rel_on_expire': self.conf.args.aes_rel_on_expire,
                       }
        if env.get('state') == 'A':
            uri = "/enqueue-reservation.php"
            res_payload['query_params[]'] = 'Environment_EnvId={}'.format(
                env.get('env_id'))
            r = self.conf.util_server.get(uri=uri, params=res_payload)
            if r.status_code != requests.codes.ok:
                raise AES(message="Problem with AES trying to enqueue a reservation "
                          "for environment '{}', please retry".format(env.get('env_id')))

            # SQL issues can cause various problems which come back as ok=200
            filter_list = ["have an error"]
            matching = [xs for xs in filter_list if xs in r.text]
            if len(matching):
                raise AES(message="OpTestSystem AES encountered an error,"
                          " check the syntax of your query and retry, Exception={}"
                          .format(r.text))

            aes_response_json = r.json()

            if aes_response_json['status'] == 0:
                new_res_id = aes_response_json['result']
            return new_res_id  # None if status not zero
        else:
            if env.get('state') == 'R' and \
                    env.get('res_email') == self.conf.args.aes_user and \
                    self.conf.args.aes_add_locktime != 0:
                time_dict = self.aes_add_time(env=env,
                                              locktime=self.conf.args.aes_add_locktime)
                return env.get('res_id')
            return new_res_id  # return None, nothing works

    def aes_lock(self, args, lock_dict):
        environments, search_criteria = self.aes_get_environments(args)
        for env in environments:
            # store the new reservation id in the callers instance
            # since we need to cleanup if aes_get_creds fails
            lock_dict['res_id'] = self.aes_lock_env(env=env)
            if lock_dict['res_id'] is not None:
                # get the database join info for the env
                creds_env = self.aes_get_env(env)
                # we need lock_dict filled in here
                # in case exception thrown in aes_get_creds
                lock_dict['name'] = env.get('name')
                lock_dict['Group_Name'] = env.get('group').get('name')
                lock_dict['envs'] = environments
                self.aes_get_creds(creds_env, args)
                return lock_dict
            else:  # it was not Available
                # if only one environment, was it us ?
                # if so extend the reservation
                if len(environments) == 1:
                    if env.get('res_email') == self.conf.args.aes_user:
                        if env.get('state') == 'R':
                            if env.get('res_length') != 0:
                                lock_dict['res_id'] = env.get('res_id')
                                # aes_add_time can fail if reservation
                                # about to expire or conflicts
                                time_dict = self.aes_add_time(env=env,
                                                              locktime=self.conf.args.aes_add_locktime)
                            creds_env = self.aes_get_env(env)
                            # we need lock_dict filled in here
                            # in case exception thrown in aes_get_creds
                            lock_dict['res_id'] = env.get('res_id')
                            lock_dict['name'] = env.get('name')
                            lock_dict['Group_Name'] = env.get(
                                'group').get('name')
                            lock_dict['envs'] = environments
                            self.aes_get_creds(creds_env, args)
                            return lock_dict
        lock_dict['res_id'] = None
        lock_dict['name'] = None
        lock_dict['Group_Name'] = None
        lock_dict['envs'] = environments
        # we did not find anything able to be reserved
        # return the list we looked thru
        return lock_dict

    def hostlocker_lock(self, args):
        args_dict = vars(args)

        # we need hostlocker_user first thing in case exceptions
        if self.conf.args.hostlocker_user is None:
            self.conf.args.hostlocker_user = pwd.getpwuid(os.getuid()).pw_name

        if self.conf.util_server is None:
            self.setup()

        uri = "/host/{}/".format(self.conf.args.hostlocker)
        try:
            r = self.conf.util_server.get(uri=uri)
        except Exception as e:
            log.debug("hostlocker_lock unable to query Exception={}".format(e))
            raise HostLocker(message="OpTestSystem HostLocker unable to query "
                             "HostLocker, check that your VPN/SSH tunnel is properly"
                             " configured and open, proxy configured as '{}' Exception={}"
                             .format(self.conf.args.hostlocker_proxy, e))

        if r.status_code != requests.codes.ok:
            raise HostLocker(message="OpTestSystem did NOT find the host '{}' "
                             "in HostLocker, please update and retry"
                             .format(self.conf.args.hostlocker))

        # parse the hostlocker comment for op-test settings
        host = r.json()[0]
        hostlocker_comment = []
        hostlocker_comment = host['comment'].splitlines()

        # Ignore anything before the [op-test] marker, as a fallback we try
        # to parse everything if there's no marker.
        offset = 0
        for i, line in enumerate(hostlocker_comment):
            if line.find("[op-test]") == 0:
                offset = i
                break

        for key in list(args_dict.keys()):
            for l in hostlocker_comment[offset:]:
                line = l.strip()
                if line.startswith(key + ":"):
                    value = re.sub(key + ':', "", line).strip()
                    args_dict[key] = value

                    if "password" in key:
                        log_value = "<hidden>"
                    else:
                        log_value = value

                    log.debug(
                        "Hostlocker config: {} = {}".format(key, log_value))

                    break

        uri = "/lock/"
        payload = {'host': self.conf.args.hostlocker,
                   'user': self.conf.args.hostlocker_user,
                   'expiry_time': self.conf.args.hostlocker_locktime}
        try:
            r = self.conf.util_server.post(uri=uri, data=payload)
        except Exception as e:
            raise HostLocker(message="OpTestSystem HostLocker unable to "
                             "acquire lock from HostLocker, see Exception={}".format(e))

        if r.status_code == requests.codes.locked:  # 423
            rc, lockers = self.hostlocker_locked()
            # MESSAGE 'unable to lock' string must be kept in same line to be filtered
            raise HostLocker(message="OpTestSystem HostLocker unable to lock"
                             " Host '{}' is locked by '{}', please unlock and retry"
                             .format(self.conf.args.hostlocker, lockers))
        elif r.status_code == requests.codes.conflict:  # 409
            raise HostLocker(message="OpTestSystem HostLocker Host '{}' is "
                             "unusable, please pick another host and retry"
                             .format(self.conf.args.hostlocker))
        elif r.status_code == requests.codes.bad_request:  # 400
            raise HostLocker(message=r.text)
        elif r.status_code == requests.codes.not_found:  # 404
            msg = ("OpTestSystem HostLocker unknown hostlocker_user '{}', "
                   "you need to have logged in to HostLocker via the web"
                   " at least once prior, please log in to HostLocker via the web"
                   " and then retry or check configuration."
                   .format(self.conf.args.hostlocker_user))
            raise HostLocker(message=msg)

        log.info("OpTestSystem HostLocker reserved host '{}' "
                 "hostlocker-user '{}'".format(self.conf.args.hostlocker,
                                               self.conf.args.hostlocker_user))

    def hostlocker_locked(self):
        # if called during signal handler cleanup
        # we may not have user yet
        if self.conf.args.hostlocker_user is None:
            return 1, []
        if self.conf.util_server is None:
            self.setup()
        uri = "/host/{}/".format(self.conf.args.hostlocker)
        try:
            r = self.conf.util_server.get(uri=uri)
        except HTTPCheck as check:
            log.debug("HTTPCheck Exception={} check.message={}".format(
                check, check.message))
            raise HostLocker(message="OpTestSystem HostLocker unknown host '{}'"
                             .format(self.conf.args.hostlocker))
        except Exception as e:
            log.debug("hostlocker_locked did NOT get any host details for '{}', "
                      "please manually verify and release,  Exception={}"
                      .format(self.conf.args.hostlocker, e))
            return 1, []  # if unable to confirm, flag it

        uri = "/lock/"
        payload = {"host": self.conf.args.hostlocker}
        try:
            r = self.conf.util_server.get(uri=uri,
                                          params=payload)
            locks = r.json()
        except Exception as e:
            log.debug("hostlocker_locked did NOT get any lock details for "
                      "host '{}', please manually verify and release, Exception={}"
                      .format(self.conf.args.hostlocker, e))
            return 1, []  # if unable to confirm, flag it
        lockers = []
        log.debug("locks JSON: {}".format(locks))
        try:
            for l in locks:
                lockers.append(str(l.get('locker')))
                if l.get('locker') == self.conf.args.hostlocker_user:
                    # lockers list is incomplete but only if we don't
                    # find hostlocker_user do we care
                    return 1, lockers
            return 0, lockers
        except Exception as e:
            log.debug("LOCKERS lockers={} Exception={}".format(lockers, e))

    def hostlocker_unlock(self):
        if self.conf.util_server is None:
            self.setup()
        uri = "/lock/"
        payload = {"host": self.conf.args.hostlocker,
                   "user": self.conf.args.hostlocker_user}
        try:
            r = self.conf.util_server.get(uri=uri,
                                          params=payload)
        except HTTPCheck as check:
            log.debug("HTTPCheck Exception={} check.message={}".format(
                check, check.message))
            msg = ("OpTestSystem HostLocker unexpected case hostlocker-user '{}', "
                   "you would need to have logged in to HostLocker via the web"
                   " at least once prior, manually verify and release, see Exception={}"
                   .format(self.conf.args.hostlocker_user, check))
            raise HostLocker(message=msg)
        except Exception as e:
            log.info("OpTestSystem HostLocker hostlocker_unlock tried to "
                     "unlock host '{}' hostlocker-user '{}' but encountered a problem, "
                     "manually verify and release, see Exception={}"
                     .format(self.conf.args.hostlocker,
                             self.conf.args.hostlocker_user, e))
            return

        locks = r.json()
        if len(locks) == 0:
            # Host is not locked, so just return
            log.debug("hostlocker_unlock tried to delete a lock but it was "
                      "NOT there, see details={}".format(locks))
            return

        if len(locks) > 1:
            # this may never happen, but it came up in debug
            # with hardcoded changes to check error paths
            log.warning("hostlocker_unlock tried to delete lock for "
                        "host '{}' but we found multiple locks and we should "
                        "have only received hostlocker-user '{}' we queried "
                        "for, please manually verify and release"
                        .format(self.conf.args.hostlocker,
                                self.conf.args.hostlocker_user))
            return

        if locks[0].get('locker') != self.conf.args.hostlocker_user:
            log.debug("hostlocker_unlock found that the locker did not "
                      "match the hostlocker_user '{}'".format(self.conf.args.hostlocker_user))
        uri = "/lock/{}".format(locks[0].get('id'))
        try:
            r = self.conf.util_server.delete(uri=uri)
        except HTTPCheck as check:
            log.debug("HTTPCheck hostlocker_unlock tried to delete a lock"
                      " but encountered an HTTP problem, "
                      "Exception={} check.message={}".format(check, check.message))
            raise HostLocker(message="hostlocker_unlock tried to delete a lock "
                             "but it was NOT there")
        except Exception as e:
            log.debug("hostlocker_unlock tried to delete a lock but it was "
                      "NOT there, see Exception={}".format(e))

    def mambo_run_command(self, term_obj, command, timeout=60, retry=0):
        expect_prompt = "systemsim %"
        term_obj.get_console().sendline(command)
        rc = term_obj.get_console().expect(
            [expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
        output_list = []
        output_list += term_obj.get_console().before.replace("\r\r\n", "\n").splitlines()
        try:
            del output_list[:1]  # remove command from the list
        except Exception as e:
            pass  # nothing there
        return output_list

    def mambo_enter(self, term_obj):
        term_obj.get_console().sendcontrol('c')
        rc = term_obj.get_console().expect(
            ["systemsim %", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        if rc != 0:
            raise UnexpectedCase(state="Mambo", message="We tried to send control-C"
                                 " to Mambo and we failed, probably just retry")

    def mambo_exit(self, term_obj):
        # this method will remove the mysim go from the output
        expect_prompt = self.build_prompt(term_obj.prompt) + "$"
        term_obj.get_console().sendline("mysim go")
        rc = term_obj.get_console().expect(
            ["mysim go", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        output_list = []
        output_list += term_obj.get_console().before.replace("\r\r\n", "\n").splitlines()
        try:
            del output_list[:1]  # remove command from the list
        except Exception as e:
            pass  # nothing there
        return output_list

class Server(object):
    '''
    Generic Server Requests Session Object to abstract retry and error
    handling logic.  There are two common uses of the requests
    session object:
    1 - Single Request with no retry.  Create the Server instance with
    minutes set to None.  This will flag the calls to cycle once and
    return non-OK requests back to the caller for handling.
    Special case is the login needed, that case will be caught and
    login attempted and original request retried.
    2 - Request calls which need to be tolerant of communication
    glitches and possible server disconnections.  Caller must create
    the Server instance with minutes set to a value.  If the caller
    wants to modify the minutes it must be done on a call by call
    basis (create the Server instance with a default minutes value
    and if longer time needed make the change on the specific call).

    Login is done for the caller, so no need to call login, just
    make the GET/PUT/POST/DELETE call.
    '''

    def __init__(self, url=None,
                 base_url=None,
                 proxy=None,
                 username=None,
                 password=None,
                 verify=False,
                 minutes=3,
                 timeout=30):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        OpTestLogger.optest_logger_glob.setUpChildLogger("urllib3")
        self.username = username
        self.password = password
        self.session = requests.Session()
        if self.username is not None and self.password is not None:
            self.session.auth = (self.username, self.password)
        self.session.verify = verify
        self.jsonHeader = {'Content-Type': 'application/json'}
        self.xAuthHeader = {}
        self.timeout = timeout
        self.minutes = minutes
        self.session.mount('https://', HTTPAdapter(max_retries=5))
        # value.max_retries for future debug if needed
#        for key, value in self.session.adapters.items():
#            log.debug("max_retries={}".format(value.max_retries))

        if proxy:
            self.session.proxies = {"http": proxy}
        else:
            self.session.proxies = {}

        self.base_url = url + (base_url if base_url else "")

    def _url(self, suffix):
        return ''.join([self.base_url, suffix])

    def login(self, username=None, password=None):
        if username is None:
            username = self.username
        if password is None:
            password = self.password
        uri = "/login"
        payload = {"data": [username, password]}
        # make direct call to requests post, by-pass loop_it
        try:
            r = self.session.post(self._url(uri),
                                  headers=self.jsonHeader,
                                  json=payload)
            if r.status_code != requests.codes.ok:
                log.debug("Requests post problem with logging "
                          "in, r.status_code={} r.text={} r.headers={} "
                          "r.request.headers={}"
                          .format(r.status_code, r.text,
                                  r.headers, r.request.headers))
                raise HTTPCheck(message="Requests post problem logging in,"
                                " check that your credentials are properly setup,"
                                " r.status_code={} r.text={} r.headers={} "
                                " r.request.headers={} username={} password={}"
                                .format(r.status_code, r.text, r.headers,
                                        r.request.headers, username, password))
            cookie = r.headers['Set-Cookie']
            match = re.search('SESSION=(\w+);', cookie)
            if match:
                self.xAuthHeader['X-Auth-Token'] = match.group(1)
                self.jsonHeader.update(self.xAuthHeader)
            json_data = json.loads(r.text)
            log.debug("r.status_code={} json_data['status']={}"
                      " r.text={} r.headers={} r.request.headers={}"
                      .format(r.status_code, json_data['status'],
                              r.text, r.headers, r.request.headers))
            if (json_data['status'] != "ok"):
                log.debug("Requests COOKIE post problem logging in,"
                          " check that your credentials are properly setup,"
                          " r.status_code={} r.text={} r.headers={} "
                          " r.request.headers={} username={} password={}"
                          .format(r.status_code, r.text, r.headers,
                                  r.request.headers, username, password))
                raise HTTPCheck(message="Requests COOKIE post problem logging in,"
                                " check that your credentials are properly setup,"
                                " r.status_code={} r.text={} r.headers={} "
                                " r.request.headers={} username={} password={}"
                                .format(r.status_code, r.text, r.headers,
                                        r.request.headers, username, password))
        except Exception as e:
            log.debug("Requests post problem, check that your "
                      "credentials are properly setup URL={} username={} "
                      "password={}, Exception={}"
                      .format(self._url(uri), username, password, e))
            raise HTTPCheck(message="Requests post problem, check that your "
                            "credentials are properly setup URL={} username={} "
                            "password={}, Exception={}"
                            .format(self._url(uri), username, password, e))
        return r

    def logout(self, uri=None):
        uri = "/logout"
        payload = {"data": []}
        try:
            # make direct call to requests post, by-pass loop_it
            # we only try for a short time (seconds) in case things are hung up
            r = self.session.post(self._url(uri), json=payload, timeout=30)
            if r.status_code != requests.codes.ok:
                log.debug("Requests post problem with logging "
                          "out, r.status_code={} r.text={} r.headers={} "
                          "r.request.headers={}"
                          .format(r.status_code, r.text,
                                  r.headers, r.request.headers))
            return r
        except Exception as e:
            log.debug("Requests post problem logging out"
                      " URL={} Exception={}".format(self._url(uri), e))

    def get(self, **kwargs):
        kwargs['cmd'] = 'get'
        r = self.loop_it(**kwargs)
        return r

    def put(self, **kwargs):
        kwargs['cmd'] = 'put'
        r = self.loop_it(**kwargs)
        return r

    def post(self, **kwargs):
        kwargs['cmd'] = 'post'
        r = self.loop_it(**kwargs)
        return r

    def delete(self, **kwargs):
        kwargs['cmd'] = 'delete'
        r = self.loop_it(**kwargs)
        return r

    def loop_it(self, **kwargs):
        default_vals = {'cmd': None, 'uri': None, 'data': None,
                        'json': None, 'params': None, 'minutes': None,
                        'files': None, 'stream': False,
                        'verify': False, 'headers': None}
        for key in default_vals:
            if key not in list(kwargs.keys()):
                kwargs[key] = default_vals[key]

        command_dict = {'get': self.session.get,
                        'put': self.session.put,
                        'post': self.session.post,
                        'delete': self.session.delete,
                        }
        if kwargs['minutes'] is not None:
            loop_time = time.time() + 60*kwargs['minutes']
        else:
            loop_time = time.time() + 60*5  # enough time to cycle
        while True:
            if time.time() > loop_time:
                raise HTTPCheck(message="HTTP \"{}\" problem, we timed out "
                                "trying URL={} PARAMS={} DATA={} JSON={} Files={}, we "
                                "waited {} minutes, check the debug log for more details"
                                .format(kwargs['cmd'], self._url(kwargs['uri']),
                                        kwargs['params'], kwargs['data'], kwargs['json'],
                                        kwargs['files'], kwargs['minutes']))
            try:
                r = command_dict[kwargs['cmd']](self._url(kwargs['uri']),
                                                params=kwargs['params'],
                                                data=kwargs['data'],
                                                json=kwargs['json'],
                                                files=kwargs['files'],
                                                stream=kwargs['stream'],
                                                verify=kwargs['verify'],
                                                headers=kwargs['headers'],
                                                timeout=self.timeout)
            except Exception as e:
                # caller did not want any retry so give them the exception
                log.debug("loop_it Exception={}".format(e))
                if kwargs['minutes'] is None:
                    raise e
                time.sleep(5)
                continue
            if r.status_code == requests.codes.unauthorized:  # 401
                try:
                    log.debug("loop_it unauthorized, trying to login")
                    self.login()
                    continue
                except Exception as e:
                    log.debug(
                        "Unauthorized login failed, Exception={}".format(e))
                    if kwargs['minutes'] is None:
                        # caller did not want retry so give them the exception
                        raise e
                    time.sleep(5)
                    continue
            if r.status_code == requests.codes.ok:
                log.debug("OpTestSystem HTTP r={} r.status_code={} r.text={}"
                          .format(r, r.status_code, r.text))
                return r
            else:
                if kwargs['minutes'] is None:
                    # caller did not want any retry so give them what we have
                    log.debug("OpTestSystem HTTP (no retry) r={} r.status_code={} r.text={}"
                              .format(r, r.status_code, r.text))
                    return r
            time.sleep(5)

    def close(self):
        self.session.close()

##
# @brief Pings 2 packages to system under test
#
# @param i_ip @type string: ip address of system under test
# @param i_try @type int: number of times the system is
#        pinged before returning Failed
#
# @return   BMC_CONST.PING_SUCCESS when PASSED or
#           raise OpTestError when FAILED
#
def ping(i_ip, i_try=1, totalSleepTime=BMC_CONST.HOST_BRINGUP_TIME):
    if i_ip == None:
        raise ParameterCheck(message="PingFunc has i_ip set to 'None', "
                             "check your configuration and setup")
    sleepTime = 0
    while(i_try != 0):
        p1 = subprocess.Popen(["ping", "-c 2", str(i_ip)],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              universal_newlines=True,
                              encoding='utf-8')
        stdout_value, stderr_value = p1.communicate()

        if(stdout_value.__contains__("2 received")):
            log.debug(i_ip + " is pinging")
            return BMC_CONST.PING_SUCCESS

        else:
            # need to print message otherwise no interactive feedback
            # and user left guessing something is not happening
            log.info("PingFunc is not pinging '{}', waited {} of {}, {} "
                     "more loop cycles remaining, you may start to check "
                     "your configuration for bmc_ip or host_ip"
                     .format(i_ip, sleepTime, totalSleepTime, i_try))
            log.debug("%s is not pinging (Waited %d of %d, %d more "
                      "loop cycles remaining)" % (i_ip, sleepTime,
                                                  totalSleepTime, i_try))
            time.sleep(1)
            sleepTime += 1
            if (sleepTime == totalSleepTime):
                i_try -= 1
                sleepTime = 0

    log.error("'{}' is not pinging and we tried many times, "
              "check your configuration and setup.".format(i_ip))
    raise ParameterCheck(message="PingFunc fails to ping '{}', "
                         "check your configuration and setup and manually "
                         "verify and release any reservations".format(i_ip))


#FIXME: fold this into the above?
def ping_mtu_check(i_ip, i_try=1, totalSleepTime=BMC_CONST.HOST_BRINGUP_TIME):
    if i_ip == None:
        raise ParameterCheck(message="PingMTUCheck has i_ip set to 'None', "
            "check your configuration and setup")
    sleepTime = 0;
    while(i_try != 0):
        p1 = subprocess.Popen(["ping", "-M", "do", "-s 1400", "-c 5", str(i_ip)],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              universal_newlines=True,
                              encoding='utf-8')
        stdout_value, stderr_value = p1.communicate()

        if(stdout_value.__contains__("5 received")):
            log.debug("Ping successfully verified MTU discovery check (prohibit fragmentation), ping -M do -s 1400 -c 5 {}".format(i_ip))
            return BMC_CONST.PING_SUCCESS

        else:
            # need to print message otherwise no interactive feedback
            # and user left guessing something is not happening
            log.info("PingMTUCheck is not able to successfully verify '{}', waited {} of {}, {} "
                     "more loop cycles remaining, you may start to check "
                     "your configuration for bmc_ip or host_ip"
                     .format(i_ip, sleepTime, totalSleepTime, i_try))
            log.debug("%s is not able to successfully verify MTU discovery (Waited %d of %d, %d more "
                      "loop cycles remaining)" % (i_ip, sleepTime,
                      totalSleepTime, i_try))
            time.sleep(1)
            sleepTime += 1
            if (sleepTime == totalSleepTime):
                i_try -= 1
                sleepTime = 0

    log.warning("'{}' is not able to successfully verify MTU discovery (prohibit fragmentation) and we tried many times, "
              "check your configuration and setup.".format(i_ip))
    raise ParameterCheck(message="PingMTUCheck fails to verify MTU discovery (prohibit fragmentation) '{}', "
        "check your configuration and setup manually ".format(i_ip))

# It waits for a ping to fail, Ex: After a BMC/FSP reboot
def ping_fail_check(i_ip):
    cmd = "ping -c 1 " + i_ip + " 1> /dev/null; echo $?"
    count = 0
    while count < 500:
        output = subprocess.getstatusoutput(cmd)
        if output[1] != '0':
            log.debug("IP %s Comes down" % i_ip)
            break
        count = count + 1
        time.sleep(2)
    else:
        log.debug("IP %s keeps on pinging up" % i_ip)
        return False
    return True



def copyFilesToDest(hostfile, destid, destName, destPath, passwd):
    arglist = (
        "sshpass",
        "-p", passwd,
        "/usr/bin/scp",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        hostfile,
        "{}@{}:{}".format(destid, destName, destPath))
    log.debug(' '.join(arglist))
    subprocess.check_call(arglist)

def copyFilesFromDest(destid, destName, destPath, passwd, sourcepath):
    arglist = (
        "sshpass",
        "-p", passwd,
        "/usr/bin/scp",
        "-r",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "{}@{}:{}".format(destid, destName, destPath),
        sourcepath)
    log.debug(' '.join(arglist))
    subprocess.check_output(arglist)
