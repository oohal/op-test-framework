#!/usr/bin/env python3

import os
import pytest

import optest.config

def get_config(sys_type):
    '''
    By their nature testing the system subclasses requires access to a system
    of the right type. Check for a config file and skip the test if we don't
    have it.
    '''

    conf = 'test_configs/{}.conf'.format(sys_type)
    if not os.path.exists(conf):
        pytest.skip("{} missing, unable to test".format(conf))

    return optest.config.OpTestConfiguration(config=conf)
