#!/bin/sh

if [ "$0" = "$_" ]; then
	echo "this script should not be called directly"
	exit 1;
fi

NAME=./run_fd_test.sh

TEST_CNT=0
TEST_PIPE=./test-pipe

do_memcr_test()
{
	if [ -z "$1" ]; then
		MEMCR_ENV=""
	else
		MEMCR_ENV="$1 "
	fi

	MEMCR_CMD="$DO$MEMCR_ENV$MEMCR -d /tmp $2"
	TEST=$3

	TEST_CNT=$((TEST_CNT + 1))
	echo "${WHITE}[test $TEST_CNT] $MEMCR_CMD -p .. for $TEST${NOFMT}"

	mkfifo $TEST_PIPE

	# start the test
	./"$TEST" $TEST_PIPE &
	TPID=$!

	# wait for test to be ready
	cat $TEST_PIPE
	rm $TEST_PIPE

	# memcr
	$MEMCR_CMD -p $TPID
	RET=$?
	if [ $RET -ne 0 ]; then
		echo "${RED}[test $TEST_CNT] failed, memcr exit code is $RET${NOFMT}"
		kill $TPID
		return 1
	fi

	# stop the test
	kill -USR1 $TPID
	wait $TPID
	RET=$?
	if [ $RET -ne 0 ]; then
		echo "${RED}[test $TEST_CNT] failed, ${TEST} exit code is $RET${NOFMT}"
		return 1
	fi

	echo "${GREEN}[test $TEST_CNT] passed${NOFMT}"
	return 0
}

# remove stale test pipe (if any)
rm -f $TEST_PIPE

TESTS="test-fd"

echo "${BOLD}[+] $NAME start${NOFMT}"

# basic tests
for OPT in "" "--proc-mem" "--rss-file" "--proc-mem --rss-file"; do
	for TEST in $TESTS; do
		do_memcr_test "" "-n $OPT" "$TEST" || exit 1
	done
done

echo "${BOLD}[+] $NAME $TEST_CNT tests passed${NOFMT}"

TESTS_DONE=$((TESTS_DONE + TEST_CNT))
