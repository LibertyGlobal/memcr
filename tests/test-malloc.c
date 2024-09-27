#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#define PFX "[test-malloc] "

#define TEST_SIZE (16 * 1024 * 1024) /* 16 MB */

static volatile sig_atomic_t signalled;

static char mema[TEST_SIZE];

static void sighandler(int num)
{
	signalled = num;
}

int main(int argc, char *argv[])
{
	int ret;
	void *memb;

	signal(SIGUSR1, sighandler);

	printf(PFX "pid %d\n", getpid());

	memset(mema, 0x5b, sizeof(mema));

	memb = malloc(TEST_SIZE);
	assert(memb);

	memset(mema, 0x5b, sizeof(mema));
	memcpy(memb, mema, sizeof(mema));

	ret = memcmp(mema, memb, sizeof(mema));
	assert(ret == 0);

	printf(PFX "mema %d kB @ %p\n", TEST_SIZE / 1024, mema);
	printf(PFX "memb %d kB @ %p\n", TEST_SIZE / 1024, memb);

	printf(PFX "waiting for SIGUSR1\n");

	while (!signalled)
		usleep(10 * 1000);

	printf(PFX "signalled (%s)\n", strsignal(signalled));

	ret = memcmp(mema, memb, sizeof(mema));
	assert(ret == 0);

	printf(PFX "ok\n");

	free(memb);
	return 0;
}