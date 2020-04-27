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
import traceback
import logging
import pytest

import OpTestConfiguration
import OpTestLogger

# op-test is the parent logger
global optestlog
optestlog = logging.getLogger(OpTestLogger.optest_logger_glob.parent_logger)

OpTestConfiguration.conf = OpTestConfiguration.OpTestConfiguration()

# create loggers, take hostlocks, etc

# HACK:
def pytest_addoption(parser):
    parser.addoption("--hostlocker", action="store", help="hostlocker host to use")

@pytest.fixture(autouse=True, scope='session')
def optest_system():
        OpTestConfiguration.conf = OpTestConfiguration.OpTestConfiguration()
        OpTestConfiguration.conf.parse_args(sys.argv)
        OpTestConfiguration.conf.do_testing_setup()
        OpTestConfiguration.conf.objs()

        print("heading to outta space")
        yield
        print("back from outta space")

        # do all our cleanup, etc
        OpTestConfiguration.conf.cleanup()


