/*
 * Copyright (C) 2022 Liberty Global Service B.V.
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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "memcr.h"
#include "arch/syscall.h"

#define VERBOSE 1

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

static int finish;

void service(struct parasite_args *args);

#if VERBOSE == 1

static char *ulong_to_hstr(unsigned long v)
{
	static char buf[sizeof(unsigned long) * 3];
	char *p = buf + sizeof(buf) - 1;
	unsigned char x;

	*p = '\0';

	if (v == 0)
		*--p = '0';

	while (v) {
		x = v % 16;
		*--p = x > 9 ? ('a' + (x - 10)) : '0' + x;
		v /= 16;
	}

	return p;
}

static void print(int fd, const char *msg)
{
	int size;

	for (size = 0; msg[size] != '\0'; size++)
		;
	sys_write(fd, msg, size);
}

#else /* VERBOSE */

#define print(fd, msg) {}

#endif

#define die(txt, ret) do { \
	print(2, __stringify(__LINE__) ": " txt); \
	print(2, ulong_to_hstr(ret)); \
	print(2, "\n"); \
	__builtin_trap(); \
} while (0);


static int read(int fd, void *buf, int size)
{
	int ret;
	int done = 0;

	while (done < size) {
		ret = sys_read(fd, buf + done, size - done);
		if (ret == 0)
			break;

		if (ret < 0)
			die("sys_read() failed: ", ret);

		done += ret;
	}

	return done;
}

static int write(int fd, const void *buf, int size)
{
	int ret;
	int done = 0;

	while (done < size) {
		ret = sys_write(fd, buf + done, size - done);
		if (ret < 0)
			die("sys_write() failed: ", ret);

		done += ret;
	}

	return done;
}

static int cmd_mprotect(int cd)
{
	int ret;
	struct vm_mprotect req;

	while (1) {
		ret = read(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		ret = sys_mprotect(req.addr, req.len, req.prot);
		if (ret < 0)
			die("sys_mprotect() failed: ", ret);
	}

	return 0;
}

static int cmd_get_pages(int cd)
{
	int ret;
	struct vm_region_req req;

	while (1) {
		ret = read(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		if (req.flags & VM_REGION_TX)
			write(cd, (void *)req.vmr.addr, req.vmr.len);

		ret = sys_madvise(req.vmr.addr, req.vmr.len, MADV_DONTNEED);
		if (ret < 0)
			die("sys_madvise() failed: ", ret);
	}

	return 0;
}

static int cmd_set_pages(int cd)
{
	int ret;
	struct vm_region_req req;

	while (1) {
		ret = read(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		read(cd, (void *)req.vmr.addr, req.vmr.len);
	}

	return 0;
}

static int cmd_end(int cd)
{
	finish = 1;

	return 0;
}

static int handle_connection(int cd)
{
	int ret;
	char cmd;

	ret = sys_read(cd, &cmd, 1);
	if (ret != 1)
		die("sys_read() failed: ", ret);

	switch (cmd) {
		case CMD_MPROTECT:
			return cmd_mprotect(cd);
		case CMD_GET_PAGES:
			return cmd_get_pages(cd);
		case CMD_SET_PAGES:
			return cmd_set_pages(cd);
		case CMD_END:
			return cmd_end(cd);
		default:
			die("unhandled cmd: ", cmd);
	}

	return 0;
}

void __attribute__((__used__)) service(struct parasite_args *args)
{
	int ret;
	int srvd;

	srvd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
	if (srvd < 0)
		die("sys_socket() failed: ", srvd);

	if ((args->addr.sun_path[0] != '\0') && (args->gid > 0)) {
		ret = sys_fchmod(srvd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0)
			die("sys_fchmod() failed: ", ret);
	}

	ret = sys_bind(srvd, (struct sockaddr *)&args->addr, sizeof(args->addr));
	if (ret < 0)
		die("sys_bind() failed: ", ret);

	if (args->addr.sun_path[0] != '\0') {
		if (args->gid > 0) {
			ret = sys_chown(args->addr.sun_path, -1, args->gid);
			if (ret < 0)
				die("sys_chown() failed: ", ret);

			ret = sys_chmod(args->addr.sun_path, 0660);
			if (ret < 0)
				die("sys_chmod() failed: ", ret);
		}
		else {
			ret = sys_chmod(args->addr.sun_path, 0600);
			if (ret < 0)
				die("sys_chmod() failed: ", ret);
		}
	}

	ret = sys_listen(srvd, 1);
	if (ret < 0)
		die("sys_listen() failed: ", ret);

	while (!finish) {
		ret = sys_accept(srvd, NULL, NULL);
		if (ret < 0)
			die("sys_accept() failed: ", ret);

		handle_connection(ret);
		sys_close(ret);
	}

	sys_close(srvd);
	sys_exit(0);
}

