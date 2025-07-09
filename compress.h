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

int compress_init(const char *algo_name, const size_t max_size);

typedef int (*compress_write_fn_t)(const char *src, const size_t len, int (*xwrite)(int fd, const void *buf, size_t count), int fd);
typedef int (*compress_read_fn_t)(char *dst, const size_t len, int (*xread)(int fd, void *buf, size_t count), int fd);

extern compress_write_fn_t compress_write;
extern compress_read_fn_t compress_read;
