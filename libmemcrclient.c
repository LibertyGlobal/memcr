/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#include "memcrclient_proto.h"
#include "libmemcrclient.h"

static int xconnect(struct sockaddr *addr, socklen_t addrlen)
{
	int cd, ret;

	cd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (cd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
		return -1;
	}

	ret = connect(cd, addr, addrlen);
	if (ret < 0) {
		fprintf(stderr, "connect() failed: %m\n");
		close(cd);
		return ret;
	}

	return cd;
}

static int connect_unix(const char *path)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	return xconnect((struct sockaddr *)&addr, sizeof(addr));
}

static int connect_tcp(int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(port),
	};

	return xconnect((struct sockaddr *)&addr, sizeof(addr));
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

	return resp.resp_code;
}


int memcr_client_connect(const char* comm_location)
{
	int cd;
	int port = atoi(comm_location);

	if (port > 0)
		cd = connect_tcp(port);
	else
		cd = connect_unix(comm_location);

	if (cd < 0) {
		fprintf(stderr, "Connection creation failed!\n");
	}
	return cd;
}

void memcr_client_disconnect(const int cd)
{
	close(cd);
}

int memcr_client_checkpoint(const int cd, const unsigned int pid)
{
	struct service_command cmd = {0};

	cmd.cmd = MEMCR_CHECKPOINT;
	cmd.pid = pid;

	return send_cmd(cd, cmd);
}

int memcr_client_restore(const int cd, const unsigned int pid)
{
	struct service_command cmd = {0};

	cmd.cmd = MEMCR_RESTORE;
	cmd.pid = pid;

	return send_cmd(cd, cmd);
}
