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

#define VERBOSE 0

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define PAGE_SIZE 4096

#define BOOM() do { *((int *)NULL) = 1; } while (0)

static int bss;
static int finish;

#if defined(VERBOSE)
static char *long_to_str(long v)
{
	static char buf[64];
	char *p = &buf[64];
	int minus = 0;

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
	static char buf[64];
	char *p = &buf[64];
	unsigned char x;

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

#define print_msg() {}
#define __DEBUG__
#define print_err() {}
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

static void memcpy_page(void *dst, void *src)
{
	int i;

	for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
		*((unsigned long *)dst) = *((unsigned long *)src);
		dst += sizeof(unsigned long);
		src += sizeof(unsigned long);
	}
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

	ret = xread(cd, &req, sizeof(req));
	if (ret < 0) {
		print_err(2, "xread() failed with ret ", ret);
		BOOM();
	}

	ret = sys_mprotect(req.addr, req.len, req.prot);
	if (ret == -1) {
		print_err(2, "sys_mprotect() failed with ret ", ret);
		BOOM();
	}

	return 0;
}

#if defined(PAGE_CRC)
static uint16_t crc16_ccitt(const char *data, int length)
{
    uint16_t crc;
    uint8_t buf;
    int i, j;

    crc = 0xFFFF;

    for (i = 0; i < length; i++) {
        buf = data[i];

        for (j = 0; j < 8; j++) {
            if (((crc & 0x8000) >> 8) ^ (buf & 0x80))
                crc = (crc << 1) ^ 0x8005;
            else
                crc = (crc << 1);

            buf <<= 1;
        }
    }

    return crc;
}
#endif

static void tx_page(int fd, void *addr, int size)
{
	struct vm_page page;

	page.addr = addr;
#if defined(PAGE_CRC)
	page.crc = crc16_ccitt(addr, size);
#endif
	memcpy_page(&page.data, addr);
	xwrite(fd, &page, sizeof(page));
}

static int cmd_get_pages(int cd)
{
	int ret;
	struct vm_page_addr req;

	while (1) {
		ret = xread(cd, &req, sizeof(req));
		if (ret == 0)
			break;

		tx_page(cd, req.addr, PAGE_SIZE);

		ret = sys_madvise(req.addr, PAGE_SIZE, MADV_DONTNEED);
		if (ret < 0) {
			print_msg(2, "sys_madvise() MADV_DONTNEED of ");
			print_msg(2, ulong_to_hstr((long)req.addr));
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

	while (1) {
		struct vm_page page;
#if defined(PAGE_CRC)
		uint16_t crc;
#endif

		ret = xread(cd, &page, sizeof(page));
		if (ret == 0)
			break;

		memcpy_page(page.addr, &page.data);

#if defined(PAGE_CRC)
		crc = crc16_ccitt(page.addr, sizeof(page.data));
		if (page.crc != crc) {
			print_msg(2, "BUG: dst page ");
			print_msg(2, ulong_to_hstr((unsigned long)page.addr));
			print_msg(2, " crc mismatch ");
			print_msg(2, long_to_str(page.crc));
			print_msg(2, " != ");
			print_msg(2, long_to_str(crc));
			print_msg(2, "\n");
			BOOM();
		}
#endif
	}

	return 0;
}

static int cmd_end(int cd)
{
	finish = 1;
	return sys_write(cd, &(char){CMD_END}, 1);
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

