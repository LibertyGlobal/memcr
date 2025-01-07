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
#include <linux/fcntl.h> /* for O_* and AT_* */

#if defined(__x86_64__)
#include "x86_64/linux-abi.h"
#elif defined(__arm__)
#include "arm/linux-abi.h"
#elif defined(__aarch64__)
#include "arm64/linux-abi.h"
#elif defined(__riscv_xlen)
#include "riscv64/linux-abi.h"
#else
#error unsupported arch
#endif

#include "syscall.h"

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

int sys_mprotect(unsigned long addr, size_t len, unsigned long prot)
{
	return syscall3(__NR_mprotect, addr, len, prot);
}

int sys_madvise(unsigned long addr, size_t len, int advice)
{
	return syscall3(__NR_madvise, addr, len, advice);
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

int sys_fchmod(int fd, mode_t mode)
{
	return syscall2(__NR_fchmod, fd, mode);
}

int sys_chmod(char* path, mode_t mode)
{
#ifdef __NR_fchmodat
	return syscall4(__NR_fchmodat, AT_FDCWD, (unsigned long)path, mode, 0);
#elif defined(__NR_chmod)
	return syscall2(__NR_chmod, (unsigned long)path, mode);
#else
	return -ENOSYS;
#endif
}

int sys_chown(char* path, uid_t owner, gid_t group)
{
#ifdef __NR_fchownat
	return syscall5(__NR_fchownat, AT_FDCWD, (unsigned long)path, owner, group, 0);
#elif defined(__NR_chown)
	return syscall3(__NR_chown, (unsigned long)path, owner, group);
#else
	return -ENOSYS;
#endif
}

int sys_getuid(void)
{
	return syscall0(__NR_getuid);
}
