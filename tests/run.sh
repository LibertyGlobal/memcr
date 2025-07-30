#!/bin/sh

#set -x

set -eu

# $1 should point to memcr executable
[ -n "$1" ] || exit 1
[ -x "$1" ] || exit 2

MEMCR=$1

CUID=$(id -u)
if [ "$CUID" != "0" ]; then
	DO="sudo "
else
	DO=""
fi

# text formatting
WHITE='\033[37m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NOFMT='\033[0m'

TESTS_DONE=0
TIME_START=$(date +%s%N)

. ./run_ok_test.sh
. ./run_corrupt_test.sh
. ./run_signal_test.sh

TIME_END=$(date +%s%N)
TIME_ELAPSED_MS=$(((TIME_END - TIME_START) / 1000000))

echo "${WHITE}[+] all $TESTS_DONE tests passed, took $TIME_ELAPSED_MS ms${NOFMT}"
