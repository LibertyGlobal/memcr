/*
 * Copyright (C) 2022 Liberty Global Service B.V.
 * Copyright (C) 2025 Marcin Mikula <marcin.mikula@tooxla.com>
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

#ifndef __SYSCALL_H__
#define __SYSCALL_H__

ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
size_t sys_lseek(int fd, size_t off, int whence);
int sys_close(int fd);
int sys_mprotect(unsigned long addr, size_t len, unsigned long prot);
int sys_madvise(unsigned long addr, size_t len, int advice);
int sys_socket(int family, int type, int protocol);
int sys_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int sys_bind(int fd, struct sockaddr *addr, socklen_t len);
int sys_listen(int fd, int n);
int sys_exit(int error_code);
long sys_gettid(void);
int sys_fchmod(int fd, mode_t mode);
int sys_chmod(char* path, mode_t mode);
int sys_chown(char* path, uid_t owner, gid_t group);
int sys_getuid(void);
int sys_open(char* path, mode_t mode);

#endif
