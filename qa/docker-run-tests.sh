#!/bin/bash

set -e

docker build -f ./qa/Dockerfile.test -t ach/acash-test .
docker run -it --rm ach/acash-test ./qa/acash/full_test_suite.py
docker run -it --rm ach/acash-test ./qa/pull-tester/rpc-tests.sh
