/*
 * Copyright (C) 2025 Mariusz Kozłowski
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#define PFX "[test-fd] "

#define FD_NUM 1000

static volatile sig_atomic_t signalled;

static void sighandler(int num)
{
	signalled = num;
}

static void notify_ready(const char *pipe)
{
	int ret;
	int fd;
	char msg[64];

	fd = open(pipe, O_WRONLY);
	assert(fd >= 0);

	snprintf(msg, sizeof(msg), PFX "pid %d ready\n", getpid());
	ret = write(fd, msg, strlen(msg));
	assert(ret == strlen(msg));

	close(fd);
}

int main(int argc, char *argv[])
{
	int ret;
	int flags[FD_NUM];

	if (argc < 2)
		return 1;

	signal(SIGUSR1, sighandler);

	printf(PFX "pid %d\n", getpid());

	for (int i = 0; i < FD_NUM - 3; i++) {
		ret = open("/dev/null", O_RDWR);
		if (ret == -1) {
			perror(PFX "open");
			return 1;
		}
	}

	for (int fd = 0; fd < FD_NUM; fd++) {
		ret = fcntl(fd, F_GETFD);
		if (ret == -1) {
			perror(PFX "fcntl");
			return 1;
		}

		flags[fd] = ret;
	}

	printf(PFX "waiting for SIGUSR1\n");

	notify_ready(argv[1]);

	while (!signalled)
		usleep(10 * 1000);

	printf(PFX "signalled (%s)\n", strsignal(signalled));

	/* test that the fds are still open and have the same flags */

	for (int fd = 0; fd < FD_NUM; fd++) {
		ret = fcntl(fd, F_GETFD);

		if (ret != flags[fd]) {
			printf(PFX "not ok, %d != %d for fd %d\n", ret, flags[fd], fd);
			return 1;
		}
	}

	for (int fd = 3; fd < FD_NUM; fd++)
		close(fd);

	printf(PFX "ok\n");

	return 0;
}
