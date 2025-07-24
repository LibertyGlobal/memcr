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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef COMPRESS_LZ4
#include <lz4.h>
#endif

#ifdef COMPRESS_ZSTD
#include <zstd.h>
#endif

#include "compress.h"

#ifdef COMPRESS_LZ4
#define MAX_DATA_SIZE_LZ4 LZ4_compressBound(max_data_size)
#endif

#ifdef COMPRESS_ZSTD
#define MAX_DATA_SIZE_ZSTD ZSTD_compressBound(max_data_size)
#define ZSTD_LEVEL ZSTD_CLEVEL_DEFAULT
#endif

static size_t max_data_size;

#if defined(COMPRESS_LZ4) || defined(COMPRESS_ZSTD)
static char *data_buf;
#endif

compress_write_fn_t compress_write;
compress_read_fn_t compress_read;

#define VERBOSE 0

#define log(...) fprintf(stdout, "[x] " __VA_ARGS__)
#if VERBOSE == 1
#define dbg(...) fprintf(stdout, "[x] " __VA_ARGS__)
#else
#define dbg(...)
#endif
#define err(...) fprintf(stderr, "[x] " __VA_ARGS__)
#define log(...) fprintf(stdout, "[x] " __VA_ARGS__)

#ifdef COMPRESS_LZ4
static int lz4_write(const char *src, const size_t len, int (*_write)(int fd, const void *buf, size_t count), int fd)
{
	int ret;
	uint32_t dst_len;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, src, len, _write, fd);

	if (data_buf == NULL) {
		data_buf = (char *)malloc(MAX_DATA_SIZE_LZ4);
		if (data_buf == NULL) {
			err("%s() Failed to allocate memory for compression buffer\n", __func__);
			return -1;
		}
	}

	ret = LZ4_compress_default(src, data_buf, len, MAX_DATA_SIZE_LZ4);
	if (ret <= 0) {
		err("%s() compression error: %d\n", __func__, ret);
		return -1;
	}

	dst_len = ret;

	dbg("%s() compressed %zu -> %d bytes\n", __func__, len, dst_len);

	ret = _write(fd, &dst_len, sizeof(dst_len));
	if (ret != sizeof(dst_len)) {
		err("%s() write dst_len failed: %d\n", __func__, ret);
		return -1;
	}

	ret = _write(fd, data_buf, dst_len);
	if (ret != dst_len) {
		err("%s() write compressed data failed: %d\n", __func__, ret);
		return -1;
	}

	return len;
}

static int lz4_read(char *dst, const size_t len, int (*_read)(int fd, void *buf, size_t count), int fd)
{
	int ret;
	uint32_t src_len;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, dst, len, _read, fd);

	if (data_buf == NULL) {
		data_buf = (char *)malloc(MAX_DATA_SIZE_LZ4);
		if (data_buf == NULL) {
			err("%s() Failed to allocate memory for decompression buffer\n", __func__);
			return -1;
		}
	}

	ret = _read(fd, &src_len, sizeof(src_len));
	if (ret != sizeof(src_len)) {
		err("%s() read src_len failed: %d\n", __func__, ret);
		return -1;
	}

	if (src_len > MAX_DATA_SIZE_LZ4) {
		err("%s() src_len %u exceeds buffer size %d\n", __func__, src_len, MAX_DATA_SIZE_LZ4);
		return -1;
	}

	ret = _read(fd, data_buf, src_len);
	if (ret != src_len) {
		err("%s() read compressed data failed: %d\n", __func__, ret);
		return -1;
	}

	ret = LZ4_decompress_safe(data_buf, dst, src_len, len);
	if (ret <= 0) {
		err("%s() decompression error: %d\n", __func__, ret);
		return -1;
	}

	return len;
}
#endif

#ifdef COMPRESS_ZSTD
static int zstd_write(const char *src, const size_t len, int (*_write)(int fd, const void *buf, size_t count), int fd)
{
	int ret;
	uint32_t dst_len;
	size_t size;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, src, len, _write, fd);

	if (data_buf == NULL) {
		data_buf = (char *)malloc(MAX_DATA_SIZE_ZSTD);
		if (data_buf == NULL) {
			err("%s() Failed to allocate memory for compression buffer\n", __func__);
			return -1;
		}
	}

	size = ZSTD_compress(data_buf, MAX_DATA_SIZE_ZSTD, src, len, ZSTD_LEVEL);
	if (ZSTD_isError(size)) {
		err("%s() compression error: %s\n", __func__, ZSTD_getErrorName(size));
		return -1;
	}

	dst_len = size;

	dbg("%s() compressed %zu -> %d bytes\n", __func__, len, dst_len);

	ret = _write(fd, &dst_len, sizeof(dst_len));
	if (ret != sizeof(dst_len)) {
		err("%s() write dst_len failed: %d\n", __func__, ret);
		return -1;
	}

	ret = _write(fd, data_buf, dst_len);
	if (ret != dst_len) {
		err("%s() write compressed data failed: %d\n", __func__, ret);
		return -1;
	}

	return len;
}

static int zstd_read(char *dst, const size_t len, int (*_read)(int fd, void *buf, size_t count), int fd)
{
	int ret;
	uint32_t src_len;
	size_t size;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, dst, len, _read, fd);

	if (data_buf == NULL) {
		data_buf = (char *)malloc(MAX_DATA_SIZE_ZSTD);
		if (data_buf == NULL) {
			err("%s() Failed to allocate memory for decompression buffer\n", __func__);
			return -1;
		}
	}

	ret = _read(fd, &src_len, sizeof(src_len));
	if (ret != sizeof(src_len)) {
		err("%s() read src_len failed: %d\n", __func__, ret);
		return -1;
	}

	if (src_len > MAX_DATA_SIZE_ZSTD) {
		err("%s() src_len %u exceeds buffer size %zu\n", __func__, src_len, MAX_DATA_SIZE_ZSTD);
		return -1;
	}

	ret = _read(fd, data_buf, src_len);
	if (ret != src_len) {
		err("%s() read compressed data failed: %d\n", __func__, ret);
		return -1;
	}

	size = ZSTD_decompress(dst, len, data_buf, src_len);
	if (ZSTD_isError(size)) {
		err("%s() decompression error: %s\n", __func__, ZSTD_getErrorName(size));
		return -1;
	}

	return len;
}
#endif

static int plain_write(const char *src, const size_t len, int (*_write)(int fd, const void *buf, size_t count), int fd)
{
	int ret;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, src, len, _write, fd);

	ret = _write(fd, src, len);
	if (ret != len) {
		err("%s() write data failed: %d\n", __func__, ret);
		return -1;
	}

	return len;
}

static int plain_read(char *dst, const size_t len, int (*_read)(int fd, void *buf, size_t count), int fd)
{
	int ret;

	dbg("%s(%p, %zu, %p, %d)\n", __func__, dst, len, _read, fd);

	ret = _read(fd, dst, len);
	if (ret != len) {
		err("%s() read data failed: %d\n", __func__, ret);
		return -1;
	}

	return ret;
}


static int select_algorithm(const char *algo)
{
	dbg("%s(%s)\n", __func__, algo);

	if (!algo) {
		compress_write = plain_write;
		compress_read = plain_read;

		log("compress: no\n");

		return 0;
	}

	if (!strcmp(algo, "lz4") || !strcmp(algo, "LZ4")) {
#ifdef COMPRESS_LZ4
		compress_write = lz4_write;
		compress_read = lz4_read;

		log("compress: LZ4\n");

		return 0;
#else
		err("compression not available, recompile with COMPRESS_LZ4=1\n");
		return 1;
#endif
	}

	if (!strcmp(algo, "zstd") || !strcmp(algo, "ZSTD")) {
#ifdef COMPRESS_ZSTD
		compress_write = zstd_write;
		compress_read = zstd_read;

		log("compress: ZSTD, level %d\n", ZSTD_LEVEL);

		return 0;
#else
		err("compression not available, recompile with COMPRESS_ZSTD=1\n");
		return 1;
#endif
	}

	err("unsupported compression: %s\n", algo);
	return 1;
}

int compress_init(const char *algorithm, const size_t max_size)
{
	int ret;

	dbg("%s(%s, %zu)\n", __func__, algorithm, max_size);

	ret = select_algorithm(algorithm);
	if (ret)
		return ret;

	max_data_size = max_size;

	return 0;
}

