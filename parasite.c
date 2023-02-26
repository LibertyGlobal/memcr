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

#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>

#include "memcr.h"

#include "arch/syscall.h"

#define VERBOSE 1

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define PAGE_SIZE 4096

#define BOOM() do { *((int *)NULL) = 1; } while (0)

static int bss;
static int finish;

#if VERBOSE == 1
static char *long_to_str(long v)
{
	static char buf[sizeof(unsigned long) * 3];
	char *p = buf + sizeof(buf) - 1;
	int minus = 0;

	*p = '\0';

	if (v == 0) {
		*--p = '0';
		return p;
	}

	if (v < 0) {
		minus = 1;
		v = -v;
	}

	while (v) {
		*--p = '0' + (v % 10);
		v /= 10;
	}

	if (minus)
		*--p = '-';

	return p;
}

static char *ulong_to_hstr(unsigned long v)
{
	static char buf[sizeof(unsigned long) * 3];
	char *p = buf + sizeof(buf) - 1;
	unsigned char x;

	*p = '\0';

	if (v == 0) {
		*--p = '0';
		return p;
	}

	while (v) {
		x = v % 16;
		*--p = x > 9 ? ('a' + (x - 10)) : '0' + x;
		v /= 16;
	}

	return p;
}

static void print_msg(int fd, const char *msg)
{
	int size;

	for (size = 0; msg[size] != '\0'; size++)
		;
	sys_write(fd, msg, size);
}

#define __DEBUG__ do { \
	print_msg(1, __func__); \
	print_msg(1, "() +" __stringify(__LINE__) "\n"); \
} while (0);

#define print_err(fd, txt, ret) do { \
	print_msg((fd), __func__); \
	print_msg((fd), "() +" __stringify(__LINE__) ": " txt); \
	print_msg((fd), long_to_str(ret)); \
	print_msg((fd), "\n"); \
} while (0);

#define die(txt, ret) do { \
	print_msg(2, __func__); \
	print_msg(2, "() +" __stringify(__LINE__) ": " txt); \
	print_msg(2, long_to_str(ret)); \
	print_msg(2, "\n"); \
	*((int *)NULL) = 1; \
} while (0);
#else /* VERBOSE*/

#define print_msg(fd, msg) {}
#define __DEBUG__
#define print_err(fd, txt, ret) {}
#define die(txt, ret) { \
	*((int *)NULL) = 1; \
}
#endif

static void xstrcpy(char *dst, char *src)
{
	int idx;

	for (idx = 0; src[idx] != '\0'; idx++)
		dst[idx] = src[idx];

	dst[idx + 1] = '\0';
}

static int xread(int fd, void *buf, int size)
{
	int ret;
	int off = 0;

	while (1) {
		ret = sys_read(fd, buf + off, size - off);
		if (ret == 0)
			break;

		if (ret < 0) {
			print_err(2, "sys_read() failed with ret ", ret);
			break;
		}

		if (ret < size - off) {
			off += ret;
			continue;
		}

		return size;
	}

	return ret;
}

static int xwrite(int fd, void *buf, int size)
{
	int ret;
	int off = 0;

	while (1) {
		ret = sys_write(fd, buf + off, size - off);
		if (ret < 0) {
			print_err(2, "sys_write() failed with ret ", ret);
			break;
		}

		if (ret < size - off) {
			off += ret;
			continue;
		}

		return size;
	}

	return ret;
}

static int cmd_get_tid(int cd)
{
	pid_t tid = sys_gettid();

	return sys_write(cd, &tid, sizeof(tid));
}

static void send_skip_addr(int fd, void *addr, char d)
{
	struct vm_skip_addr sa = {
		.addr = addr,
		.desc = d,
	};

	xwrite(fd, &sa, sizeof(sa));
}

static int cmd_get_skip_addr(int cd)
{
	send_skip_addr(cd, &bss, 'b');
	return 0;
}

static int cmd_mprotect(int cd)
{
	int ret;
	struct vm_mprotect req;

	while (1) {
		ret = xread(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		if (ret < 0) {
			print_err(2, "xread() failed with ret ", ret);
			BOOM();
		}

		ret = sys_mprotect(req.addr, req.len, req.prot);
		if (ret == -1) {
			print_err(2, "sys_mprotect() failed with ret ", ret);
			BOOM();
		}
	}

	return 0;
}

static int cmd_get_pages(int cd)
{
	int ret;
	struct vm_region_req req;

	while (1) {
		ret = xread(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		if (ret < 0) {
			print_err(2, "xread() failed with ret ", ret);
			BOOM();
		}

		if (req.flags & VM_REGION_TX)
			xwrite(cd, (void *)req.vmr.addr, req.vmr.len);

		ret = sys_madvise(req.vmr.addr, req.vmr.len, MADV_DONTNEED);
		if (ret < 0) {
			print_msg(2, "sys_madvise() MADV_DONTNEED of ");
			print_msg(2, ulong_to_hstr((long)req.vmr.addr));
			print_msg(2, " failed with ");
			print_msg(2, long_to_str(ret));
			print_msg(2, "\n");
		}
	}

	return 0;
}

static int cmd_set_pages(int cd)
{
	int ret;
	struct vm_region_req req;

	while (1) {
		ret = xread(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		xread(cd, (void *)req.vmr.addr, req.vmr.len);
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
	if (ret != 1) {
		print_err(2, "sys_read() failed: ", ret);
		return ret;
	}

	switch (cmd) {
		case CMD_GET_TID:
			return cmd_get_tid(cd);
		case CMD_GET_SKIP_ADDR:
			return cmd_get_skip_addr(cd);
		case CMD_MPROTECT:
			return cmd_mprotect(cd);
		case CMD_GET_PAGES:
			return cmd_get_pages(cd);
		case CMD_SET_PAGES:
			return cmd_set_pages(cd);
		case CMD_END:
			return cmd_end(cd);
		default:
			print_err(2, "unhandled cmd ", cmd);
			break;
	}

	return 0;
}

void __attribute__((__used__)) service(unsigned int cmd, void *args)
{
	int ret;
	struct parasite_args *pa = args;
	int srvd;
	struct sockaddr_un addr;

	srvd = sys_socket(PF_UNIX, SOCK_STREAM, 0);
	if (srvd < 0) {
		die("sys_socket() failed: ", srvd);
	}

	addr.sun_family = PF_UNIX;
	xstrcpy(addr.sun_path, pa->addr);
	if ('#' == addr.sun_path[0])
		addr.sun_path[0] = '\0';

	ret = sys_bind(srvd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		die("sys_bind() failed: ", ret);
	}

	ret = sys_listen(srvd, 8);
	if (ret < 0) {
		die("sys_listen() failed: ", ret);
	}

	while (!finish) {
		ret = sys_accept(srvd, NULL, NULL);
		if (ret < 0) {
			print_err(2, "sys_accept() failed: ", ret);
		} else {
			handle_connection(ret);
			sys_close(ret);
		}
	}

	sys_close(srvd);
	sys_exit(0);
}

