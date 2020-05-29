#!/usr/bin/env python3
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: op-test-framework/ci/source/op_ci_bmc.py $
#
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2015-2017
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
"""
op-test: run OpenPOWER test suite(s)
"""
import os
import re
import sys
import time
import logging
import pytest

from optest import config
from optest import logger

import pytest

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)

@pytest.fixture
def something(request):
    yield
    # request.node is an "item" because we use the default
    # "function" scope
    if request.node.rep_setup.failed:
        print("setting up a test failed!", request.node.nodeid)
    elif request.node.rep_setup.passed:
        if request.node.rep_call.failed:
            print("executing test failed", request.node.nodeid)

'''
# create loggers, take hostlocks, etc
# FIXME: work out what to do with all this logging stuff. We might be able to
#        just use the default logging setup...

def get_suffix(config):
    # Grab the suffix, if not given use current time
    if (config.args['suffix']):
        outsuffix = config['suffix']
    else:
        outsuffix = time.strftime("%Y%m%d%H%M%S")
    return outsuffix

def do_testing_setup(config):
    # Setup some defaults for the output options
    # Order of precedence
    # 1. cmdline arg
    # 2. env variable
    # 3. default path

    if self.args['output']:
        outdir = self.args['output']
    elif "OP_TEST_OUTPUT" in os.environ:
        outdir = os.environ["OP_TEST_OUTPUT"]
    else:
        outdir = os.path.join(self.basedir, "test-reports")

    outsuffix = "test-run-%s" % get_suffix(config)
    outdir = os.path.join(outdir, outsuffix)

    # Normalize the path to fully qualified and create if not there
    self.output = os.path.abspath(outdir)
    if (not os.path.exists(self.output)):
        os.makedirs(self.output)

    if (config.args['logdir']):
        logdir = self.args['logdir']
    elif ("OP_TEST_LOGDIR" in os.environ):
        logdir = os.environ["OP_TEST_LOGDIR"]
    else:
        logdir = self.output

    logdir = os.path.abspath(logdir)
    if (not os.path.exists(logdir)):
        os.makedirs(logdir)

    print(("Logs in: {}".format(logdir)))

    logger.optest_logger_glob.logdir = logdir

    # set up where all the logs go
    logfile = os.path.join(self.output, "%s.log" % suffix

    logcmd = "tee %s" % (logfile)
    if self.args.quiet:
        logcmd = logcmd + "> /dev/null"
        # save sh_level for later refresh loggers
        OpTestLogger.optest_logger_glob.sh_level = logging.ERROR
        OpTestLogger.optest_logger_glob.sh.setLevel(logging.ERROR)
    else:
        # we use 'cat -v' to convert control characters
        # to something that won't affect the user's terminal
        logcmd = logcmd + "| sed -u -e 's/\\r$//g'|cat -v"

        # save sh_level for later refresh loggers
        OpTestLogger.optest_logger_glob.sh_level = logging.INFO
        OpTestLogger.optest_logger_glob.sh.setLevel(logging.INFO)

    OpTestLogger.optest_logger_glob.setUpLoggerFile(
        datetime.utcnow().strftime("%Y%m%d%H%M%S%f")+'.main.log')
    OpTestLogger.optest_logger_glob.setUpLoggerDebugFile(
        datetime.utcnow().strftime("%Y%m%d%H%M%S%f")+'.debug.log')
    OpTestLogger.optest_logger_glob.optest_logger.info(
        'TestCase Log files: {}/*'.format(self.output))
    OpTestLogger.optest_logger_glob.optest_logger.info(
        'StreamHandler setup {}'.format('quiet' if self.args.quiet else 'normal'))

    self.logfile_proc = subprocess.Popen(logcmd,
                                         stdin=subprocess.PIPE,
                                         stderr=sys.stderr,
                                         stdout=sys.stdout,
                                         shell=True,
                                         universal_newlines=True,
                                         encoding='utf-8')
    self.logfile = self.logfile_proc.stdin

    # now that we have loggers, dump conf file to help debug later
    OpTestLogger.optest_logger_glob.optest_logger.debug(
        "conf file defaults={}".format(self.defaults))
    cmd = "git describe --always"
    try:
        git_output = subprocess.check_output(cmd.split())
        # log for triage of how dated the repo is
        OpTestLogger.optest_logger_glob.optest_logger.debug(
            "op-test-framework git level = {}".format(git_output))
    except Exception as e:
        OpTestLogger.optest_logger_glob.optest_logger.debug(
            "Unable to get git describe")

'''

# Add the old op-test options for finding a particular system to the
# pytest arguments. This still lets us choose the system to run op-test
# against based on the config in hostlocker, aes, or in a local config file.
def pytest_addoption(parser):
    # FIXME: these should be mutually exclusive
    parser.addoption("--hostlocker", action="store", help="host from hostlocker to test")
    parser.addoption("--aes", action="store", help="host in AES to use")
    parser.addoption("--aes-search-args", action="store", help="host in AES to use")

    parser.addoption("--config-file", action="store", help="system config file to use")

    # the logfile stuff needs to be in here:
    #basedir, suffix, anything else?
    # quiet?

@pytest.fixture(autouse=True, scope='session')
def optest_system(pytestconfig):

        test_config = config.OpTestConfiguration( \
                                    config=pytestconfig.option.config_file,
                                    aes=pytestconfig.option.aes,
                                    hostlocker=pytestconfig.option.hostlocker)

        system = test_config.create_system()

        yield system

        # do all our cleanup, etc
        test_config.cleanup()
