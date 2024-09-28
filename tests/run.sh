#!/bin/sh

#set -x

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
BOLD='\033[1m'
NOFMT='\033[0m'

TEST_CNT=0

do_memcr_test()
{
	MEMCR_CMD=$1
	TEST=$2

	TEST_CNT=$((TEST_CNT + 1))
	echo "${WHITE}[test $TEST_CNT] $MEMCR_CMD for $TEST${NOFMT}"

	# start the test
	./$TEST &
	TPID=$!

	# wait
	sleep 0.05

	# memcr
	$MEMCR_CMD -p $TPID
	if [ $? -ne 0 ]; then
		kill $TPID
		echo "${RED}[test $TEST_CNT] failed${NOFMT}"
		return 1
	fi

	# stop the test
	kill -USR1 $TPID
	wait $TPID
	if [ $? -ne 0 ]; then
		echo "${RED}[test $TEST_CNT] failed${NOFMT}"
		return 1
	fi

	echo "${GREEN}[test $TEST_CNT] passed${NOFMT}"
	return 0
}

TESTS="test-malloc"

TIME_START=$(date +%s%N)

# basic tests
for OPT in "" "--proc-mem" "--rss-file" "--proc-mem --rss-file"; do
	MEMCR_CMD="${DO}$MEMCR -n $OPT"

	for TEST in $TESTS; do
		do_memcr_test "$MEMCR_CMD" "$TEST" || exit 1
	done
done

# compression tests
if [ "$COMPRESS_LZ4" = 1 ]; then
	MEMCR_CMD="${DO}$MEMCR -n -f --compress"

	for TEST in $TESTS; do
		do_memcr_test "$MEMCR_CMD" "$TEST" || exit 1
	done
fi

# checksumming tests
if [ "$CHECKSUM_MD5" = 1 ]; then
	MEMCR_CMD="${DO}$MEMCR -n -f --checksum"

	for TEST in $TESTS; do
		do_memcr_test "$MEMCR_CMD" "$TEST" || exit 1
	done
fi

# encryption tests
if [ "$ENCRYPT" = "1" ]; then
	if [ ! -f ../libencrypt.so ]; then
		echo "${RED}libencrypt.so not found${NOFMT}"
		exit 1
	fi

	for OPT in "--rss-file" "--proc-mem --rss-file"; do
		for ENC in "" "aes-128-cbc" "aes-192-cbc" "aes-256-cbc"; do
			MEMCR_CMD="${DO}env LD_PRELOAD=../libencrypt.so $MEMCR -n $OPT --encrypt $ENC"

			for TEST in $TESTS; do
				do_memcr_test "$MEMCR_CMD" "$TEST" || exit 1
			done
		done
	done
fi

# combined tests
if [ "$COMPRESS_LZ4" = 1 ] && [ "$CHECKSUM_MD5" = 1 ] && [ "$ENCRYPT" = "1" ]; then
	MEMCR_CMD="${DO}env LD_PRELOAD=../libencrypt.so $MEMCR -n -f -z -c -e"

	for TEST in $TESTS; do
		do_memcr_test "$MEMCR_CMD" "$TEST" || exit 1
	done
fi

TIME_END=$(date +%s%N)
TIME_ELAPSED_MS=$(((TIME_END - TIME_START) / 1000000))

echo "${BOLD}[+] all $TEST_CNT tests passed, took $TIME_ELAPSED_MS ms${NOFMT}"