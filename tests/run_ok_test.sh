#!/bin/sh

if [ "$0" = "$_" ]; then
	echo "this script should not be called directly"
	exit 1;
fi

NAME=./run_ok_test.sh

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

TESTS="test-malloc"

echo "${BOLD}[+] $NAME start${NOFMT}"

# basic tests
for OPT in "" "--proc-mem" "--rss-file" "--proc-mem --rss-file"; do
	for TEST in $TESTS; do
		do_memcr_test "" "-n $OPT" "$TEST" || exit 1
	done
done

# compression tests: lz4
if [ "$COMPRESS_LZ4" = 1 ]; then
	for TEST in $TESTS; do
		do_memcr_test "" "-n -f --compress lz4" "$TEST" || exit 1
	done
fi

# compression tests: zstd
if [ "$COMPRESS_ZSTD" = 1 ]; then
	for TEST in $TESTS; do
		do_memcr_test "" "-n -f -z zstd" "$TEST" || exit 1
	done
fi

# checksumming tests
if [ "$CHECKSUM_MD5" = 1 ]; then
	for TEST in $TESTS; do
		do_memcr_test "" "-n -f --checksum" "$TEST" || exit 1
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
			for TEST in $TESTS; do
				do_memcr_test "env LD_PRELOAD=../libencrypt.so" "-n $OPT --encrypt $ENC" "$TEST" || exit 1
			done
		done
	done
fi

# combined tests: lz4 + md5 + enc
if [ "$COMPRESS_LZ4" = 1 ] && [ "$CHECKSUM_MD5" = 1 ] && [ "$ENCRYPT" = "1" ]; then
	for TEST in $TESTS; do
		do_memcr_test "env LD_PRELOAD=../libencrypt.so" "-n -f -z -c -e" "$TEST" || exit 1
	done
fi

# combined tests: zstd + md5 + enc
if [ "$COMPRESS_ZSTD" = 1 ] && [ "$CHECKSUM_MD5" = 1 ] && [ "$ENCRYPT" = "1" ]; then
	for TEST in $TESTS; do
		do_memcr_test "env LD_PRELOAD=../libencrypt.so" "-n -f -z ZSTD -c -e" "$TEST" || exit 1
	done
fi

echo "${BOLD}[+] $NAME $TEST_CNT tests passed${NOFMT}"

TESTS_DONE=$((TESTS_DONE + TEST_CNT))
