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
#include <sys/socket.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#include "x86_64/linux-abi.h"
#elif defined(__arm__)
#include "arm/linux-abi.h"
#else
#error unsupported arch
#endif

ssize_t sys_read(int fd, void *buf, size_t count)
{
	return syscall3(__NR_read, fd, (unsigned long)buf, count);
}

ssize_t sys_write(int fd, const void *buf, size_t count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
}

int sys_close(int fd)
{
	return syscall1(__NR_close, fd);
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	return syscall3(__NR_mprotect, (unsigned long)addr, len, prot);
}

int sys_madvise(void *addr, size_t len, int advice)
{
	return syscall3(__NR_madvise, (unsigned long)addr, len, advice);
}

int sys_socket(int family, int type, int protocol)
{
	return syscall3(__NR_socket, family, type, protocol);
}

int sys_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	return syscall3(__NR_accept, fd, (unsigned long)addr, (unsigned long)addrlen);
}

int sys_bind(int fd, struct sockaddr *addr, socklen_t len)
{
	return syscall3(__NR_bind, fd, (unsigned long)addr, len);
}

int sys_listen(int fd, int n)
{
	return syscall2(__NR_listen, fd, n);
}

int sys_exit(int error_code)
{
	return syscall1(__NR_exit, error_code);
}

long sys_gettid(void)
{
	return syscall0(__NR_gettid);
}
