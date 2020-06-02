#!/bin/bash -e

source op-test-venv/bin/activate
cd selftests
pytest
