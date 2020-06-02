#!/bin/bash -e

source op-test-venv/bin/activate
pytest --config-file=qemu.conf
