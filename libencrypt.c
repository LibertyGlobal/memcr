/*
 * Copyright (C) 2023 Liberty Global Service B.V.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>


#define IO_SIZE 4096
#define ROUND_UP(n, m) ((n + m) & ~(m - 1))

#define VERBOSE 0

#define log(...) fprintf(stdout, "[x] " __VA_ARGS__)
#if VERBOSE == 1
#define dbg(...) fprintf(stdout, "[x] " __VA_ARGS__)
#else
#define dbg(...)
#endif
#define err(...) fprintf(stderr, "[x] " __VA_ARGS__)


static const EVP_CIPHER *cipher;
static EVP_CIPHER_CTX *ctx;
static int block_size;
static unsigned char key[16];
static unsigned char iv[16];

/*
 * Prototypes matching memcr.
 */
int lib__open(const char *pathname, int flags, mode_t mode);
int lib__close(int fd);
int lib__read(int fd, void *buf, size_t count);
int lib__write(int fd, const void *buf, size_t count);
int lib__init(int enable, const char *arg);
int lib__fini(void);


int lib__open(const char *pathname, int flags, mode_t mode)
{
	dbg("%s(%s, 0x%x, 0x%x)\n", __func__, pathname, flags, mode);

	if (!cipher)
		return open(pathname, flags, mode);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		err("EVP_CIPHER_CTX_new() failed\n");
		return -1;
	}

	return open(pathname, flags, mode);
}

int lib__close(int fd)
{
	dbg("%s(%d)\n", __func__, fd);

	if (!cipher)
		return close(fd);

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

	return close(fd);
}

int lib__read(int fd, void *buf, size_t count)
{
	int ret;
	unsigned char *p;
	unsigned char data[IO_SIZE];
	unsigned char dec_buf[IO_SIZE + EVP_MAX_BLOCK_LENGTH];
	int dec_len;
	int bytes_read = 0;
	int bytes_todo = ROUND_UP(count, block_size);

	dbg("%s(%d, %p, %d)\n", __func__, fd, buf, (int)count);

	if (!cipher)
		return read(fd, buf, count);

	if (!ctx) {
		err("invalid cipher ctx\n");
		return -1;
	}

	ret = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
	if (ret != 1) {
		err("EVP_DecryptInit_ex() failed: %d\n", ret);
		return -1;
	}

	for (p = (unsigned char *)buf; p < (unsigned char *)buf + count; p += dec_len) {
		int size;

		if (bytes_todo - bytes_read < IO_SIZE)
			size = bytes_todo - bytes_read;
		else
			size = IO_SIZE;

		ret = read(fd, data, size);
		if (ret == 0)
			break;

		if (ret < 0) {
			err("read() failed: %m\n");
			return -1;
		}

		bytes_read += ret;

		ret = EVP_DecryptUpdate(ctx, dec_buf, &dec_len, data, ret);
		if (ret != 1) {
			err("EVP_DecryptUpdate() failed: %d\n", ret);
			return -1;
		}

		memcpy(p, dec_buf, dec_len);
	}

	if (!bytes_read)
		return 0;

	ret = EVP_DecryptFinal_ex(ctx, dec_buf, &dec_len);
	if (ret != 1) {
		err("EVP_DecryptFinal_ex() failed: %d\n", ret);
		return -1;
	}

	memcpy(p, dec_buf, dec_len);

	return count;
}

int lib__write(int fd, const void *buf, size_t count)
{
	int ret;
	unsigned char *p;
	unsigned char data[IO_SIZE + EVP_MAX_BLOCK_LENGTH];
	int enc_len;

	dbg("%s(%d, %p, %d)\n", __func__, fd, buf, (int)count);

	if (!cipher)
		return write(fd, buf, count);

	if (!ctx) {
		err("invalid cipher ctx\n");
		return -1;
	}

	ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
	if (ret != 1) {
		err("EVP_EncryptInit_ex() failed: %d\n", ret);
		return -1;
	}

	for (p = (unsigned char *)buf; p < (unsigned char *)buf + count; p += IO_SIZE) {
		int size;

		if (p > (unsigned char *)buf + count - IO_SIZE)
			size = count % IO_SIZE;
		else
			size = IO_SIZE;

		ret = EVP_EncryptUpdate(ctx, data, &enc_len, p, size);
		if (ret != 1) {
			err("EVP_EncryptUpdate() failed: %d\n", ret);
			return -1;
		}

		ret = write(fd, data, enc_len);
		if (ret < 0) {
			err("write() failed: %m\n");
			return -1;
		}
	}

	ret = EVP_EncryptFinal_ex(ctx, data, &enc_len);
	if (ret != 1) {
		err("EVP_EncryptFinal_ex() failed: %d\n", ret);
		return -1;
	}

	ret = write(fd, data, enc_len);
	if (ret < 0) {
		err("write() failed: %m\n");
		return -1;
	}

	return count;
}

int lib__init(int enable, const char *arg)
{
	int ret;
	const char *description;

	dbg("%s(%d, %s)\n", __func__, enable, arg);

	if (!enable) {
		log("encryption not enabled\n");
		return 0;
	}

	if (!arg)
		cipher = EVP_aes_128_cbc();
	else if (!strcmp(arg, "aes-128-cbc"))
		cipher = EVP_aes_128_cbc();
	else if (!strcmp(arg, "aes-192-cbc"))
		cipher = EVP_aes_192_cbc();
	else if (!strcmp(arg, "aes-256-cbc"))
		cipher = EVP_aes_256_cbc();
	else {
		err("supported ciphers are:\n" \
		    "\taes-128-cbc\n" \
		    "\taes-192-cbc\n" \
		    "\taes-256-cbc\n"
		);
		return -1;
	}

	if (!cipher) {
		err("EVP_aes_*_cbc() failed\n");
		return -1;
	}

	ret = RAND_bytes(key, sizeof(key));
	if (ret != 1) {
		err("RAND_bytes() for key failed: %d\n", ret);
		return -1;
	}

	ret = RAND_bytes(iv, sizeof(iv));
	if (ret != 1) {
		err("RAND_bytes() for iv failed: %d\n", ret);
		return -1;
	}

	description = EVP_CIPHER_name(cipher);
	block_size = EVP_CIPHER_block_size(cipher);
	if (block_size <= 0) {
		err("invalid block size\n");
		return -1;
	}

	log("using %s, block size %d\n", description, block_size);

	return 0;
}

int lib__fini(void)
{
	dbg("%s()\n", __func__);

	return 0;
}

