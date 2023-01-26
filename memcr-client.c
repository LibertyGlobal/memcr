/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#include "memcr.h"


static int xconnect(int port)
{
	int cd;
	int ret;
	struct sockaddr_in addr;
	int cnt = 0;

	cd = socket(AF_INET, SOCK_STREAM, 0);
	if (cd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(port);

retry:
	ret = connect(cd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (cnt++ < 100) {
			usleep(1*1000);
			goto retry;
		} else {
			fprintf(stderr, "connect() to 127.0.0.1:%d failed: %m\n", port);
			close(cd);
		}
	}

	return cd;
}

static int send_cmd(int cd, struct service_command cmd)
{
	int ret;
	struct service_response resp = {0};

	ret = write(cd, &cmd, sizeof(struct service_command));
	if (ret != sizeof(struct service_command)) {
		fprintf(stderr, "%s() write request failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	ret = read(cd, &resp, sizeof(struct service_response));
	if (ret != sizeof(struct service_response)) {
		fprintf(stderr, "%s() read response failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	fprintf(stdout, "Procedure finished with %s status.\n", MEMCR_OK == resp.resp_code ? "OK" : "ERROR");

	return 0;
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s -l PORT -p PID [-c -r]\n" \
		"options: \n" \
		"  -h --help\t\thelp\n" \
		"  -l --local-port\tTCP port number of localhost memcr service\n" \
		"  -p --pid\t\tprocess ID to be checkpointed / restored\n" \
		"  -c --checkpoint\tsend checkpoint command to memcr service\n" \
		"  -r --restore\t\tsend restore command to memcr service\n",
		name);
	exit(status);
}

int main(int argc, char *argv[])
{
	int ret, cd, opt;
	int checkpoint = 0;
	int restore = 0;
	int port = -1;
	int option_index;
	struct service_command cmd = {0};
	int pid = 0;

	static struct option long_options[] = {
		{ "help",       0,  0,  0},
		{ "local-port", 1,  0,  0},
		{ "pid",        1,  0,  0},
		{ "checkpoint", 0,  0,  0},
		{ "restore",    0,  0,  0},
		{ NULL,         0,  0,  0}
	};

	while ((opt = getopt_long(argc, argv, "hl:p:cr", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'l':
				port = atoi(optarg);
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'c':
				checkpoint = 1;
				break;
			case 'r':
				restore = 1;
				break;
			default: /* '?' */
				usage(argv[0], 1);
				break;
		}
	}

	if (!pid || !port) {
		fprintf(stderr, "Incorrect arguments provided!\n");
		usage(argv[0], 1);
		return -1;
	}

	if (!checkpoint && !restore) {
		fprintf(stderr, "You have to provide a command (checkpoint or restore or both)!\n");
		usage(argv[0], 1);
		return -1;
	}

	cd = xconnect(port);
	if (cd < 0)
		return cd;

	if (checkpoint) {
		fprintf(stdout, "Will checkpoint %d.\n", pid);
		cmd.cmd = MEMCR_CHECKPOINT;
		cmd.pid = pid;
		ret = send_cmd(cd, cmd);
	}

	if (restore) {
		fprintf(stdout, "Will restore %d.\n", pid);
		cmd.cmd = MEMCR_RESTORE;
		cmd.pid = pid;
		ret = send_cmd(cd, cmd);
	}

	fprintf(stdout, "Command executed, exiting.\n");
	close(cd);

	return ret;
}

