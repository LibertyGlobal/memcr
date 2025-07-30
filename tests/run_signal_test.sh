#!/bin/sh

if [ "$0" = "$_" ]; then
	echo "this script should not be called directly"
	exit 1;
fi

NAME=./run_signal_test.sh

TEST_CNT=0
TEST_PIPE=./test-pipe
MEMCR_PIPE_0=./memcr-pipe-0
MEMCR_PIPE_1=./memcr-pipe-1

do_memcr_signal_test()
{
	if [ -z "$1" ]; then
		MEMCR_ENV=""
	else
		MEMCR_ENV="$1 "
	fi

	MEMCR_CMD="$DO$MEMCR_ENV$MEMCR -d /tmp $2"
	TEST=$3
	SIGNAL=$4

	TEST_CNT=$((TEST_CNT + 1))
	echo "${WHITE}[test $TEST_CNT] $MEMCR_CMD -p .. for $TEST${NOFMT}"

	mkfifo $TEST_PIPE

	# start the test
	./"$TEST" $TEST_PIPE &
	TPID=$!

	# wait for test to be ready
	cat $TEST_PIPE
	rm $TEST_PIPE

	mkfifo $MEMCR_PIPE_0
	exec 3<>$MEMCR_PIPE_0
	mkfifo $MEMCR_PIPE_1

	# memcr checkpoint and wait
	$MEMCR_CMD -p $TPID < $MEMCR_PIPE_0 > $MEMCR_PIPE_1 2>&1 &
	MPID=$!

	# wait until checkpoint is complete
	while IFS=$'\n' read -r LINE; do
		echo "$LINE"

		case "$LINE" in
			*"press enter to restore"*)
			break
			;;
		esac
	done < $MEMCR_PIPE_1

	# send signal to TPID
	echo "${YELLOW}[test $TEST_CNT] send $SIGNAL to $TPID and restore${NOFMT}"
	kill -"$SIGNAL" $TPID

	# memcr restore
	echo "" > $MEMCR_PIPE_0

	# show remaining output
	cat $MEMCR_PIPE_1

	rm $MEMCR_PIPE_1
	exec 3>&-
	rm $MEMCR_PIPE_0

	# memcr is expected to exit with error

	wait $MPID
	RET=$?
	if [ $RET -eq 0 ]; then
		echo "${RED}[test $TEST_CNT] failed, memcr exit code is $RET${NOFMT}"
		return 1
	else
		echo "[test $TEST_CNT] MPID exit code is $RET"
	fi

	wait $TPID
	RET=$?
	if [ $RET -eq 0 ]; then
		echo "${RED}[test $TEST_CNT] failed, ${TEST} exit code is $RET${NOFMT}"
		return 1
	else
		echo "[test $TEST_CNT] TPID exit code is $RET"
	fi

	echo "${GREEN}[test $TEST_CNT] passed${NOFMT}"
	return 0
}

# remove stale test pipe (if any)
rm -f $TEST_PIPE
rm -f $MEMCR_PIPE_0
rm -f $MEMCR_PIPE_1

echo "${BOLD}[+] $NAME start${NOFMT}"

# SIGKILL test
do_memcr_signal_test "" "-f -m" "test-malloc" KILL || exit 1

# SIGTERM test
do_memcr_signal_test "" "-f -m" "test-malloc" TERM || exit 1

echo "${BOLD}[+] $NAME $TEST_CNT test passed${NOFMT}"

TESTS_DONE=$((TESTS_DONE + TEST_CNT))
