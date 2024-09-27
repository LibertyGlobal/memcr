#!/bin/sh

#set -x

# $1 should point to memcr executable
[ -n "$1" ] || exit 1
[ -x "$1" ] || exit 2

MEMCR=$1

CUID=$(id -u)
if [ "$CUID" != "0" ]; then
	DO="sudo"
else
	DO=""
fi

TESTS="test-malloc"

for TEST in $TESTS; do
	echo "######## running $TEST ########"

	# start the test
	./$TEST &

	# wait
	sleep 0.2

	# memcr
	$DO $MEMCR -p $! -n -f
	if [ $? -ne 0 ]; then
		kill $!
		echo "[-] $TEST failed"
		break
	fi

	# stop the test
	kill -USR1 $!
	wait $!
	if [ $? -eq 0 ]; then
		echo "[+] $TEST passed"
	else
		echo "[-] $TEST failed"
		break
	fi
done
