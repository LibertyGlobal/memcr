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
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#include "memcr.h"
#include "libmemcrclient.h"

static void print_version(void)
{
	fprintf(stdout, "[i] memcr-client version %s\n", GIT_VERSION);
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s -l PORT|PATH -p PID [-c -r] [-V]\n" \
		"options: \n" \
		"  -h --help\t\thelp\n" \
		"  -l --location\t\tTCP port number of localhost memcr service\n" \
		"\t\t\t or filesystem path to memcr service UNIX socket\n" \
		"  -p --pid\t\tprocess ID to be checkpointed / restored\n" \
		"  -c --checkpoint\tsend checkpoint command to memcr service\n" \
		"  -r --restore\t\tsend restore command to memcr service\n" \
		"  -V --version\t\tprint version and exit\n",
		name);
	exit(status);
}

int main(int argc, char *argv[])
{
	int ret, cd, opt;
	int checkpoint = 0;
	int restore = 0;
	int option_index;
	char *comm_location = NULL;
	int pid = 0;

	struct option long_options[] = {
		{ "help",       0,  0,  'h'},
		{ "location",   1,  0,  'l'},
		{ "pid",        1,  0,  'p'},
		{ "checkpoint", 0,  0,  'c'},
		{ "restore",    0,  0,  'r'},
		{ "version",    0,  0,  'V'},
		{ NULL,         0,  0,  0  }
	};

	while ((opt = getopt_long(argc, argv, "hl:p:crV", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'l':
				comm_location = optarg;
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
			case 'V':
				print_version();
				exit(0);
			default: /* '?' */
				usage(argv[0], 1);
				break;
		}
	}

	if (!pid || !comm_location) {
		fprintf(stderr, "Incorrect arguments provided!\n");
		usage(argv[0], 1);
		return -1;
	}

	if (!checkpoint && !restore) {
		fprintf(stderr, "You have to provide a command (checkpoint or restore or both)!\n");
		usage(argv[0], 1);
		return -1;
	}

	cd = memcr_client_connect(comm_location);

	if (cd < 0) {
		fprintf(stderr, "Connection creation failed!\n");
		return cd;
	}

	if (checkpoint) {
		fprintf(stdout, "Will checkpoint %d.\n", pid);
		ret = memcr_client_checkpoint(cd, pid);
	}

	if (restore) {
		fprintf(stdout, "Will restore %d.\n", pid);
		ret = memcr_client_restore(cd, pid);
	}

	fprintf(stdout, "Command executed, exiting.\n");
	memcr_client_disconnect(cd);

	return ret;
}
