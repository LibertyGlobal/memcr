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

#ifndef __MEMCR_H__
#define __MEMCR_H__

#include <stdint.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#if 0
#define PAGE_CRC
#endif

struct parasite_args {
	char addr[108]; /* abstract or filesystem socket address */
};

typedef enum {
	CMD_GET_TID = 1,
	CMD_GET_SKIP_ADDR,
	CMD_MPROTECT,
	CMD_GET_PAGES,
	CMD_SET_PAGES,
	CMD_END,
} memcr_cmd;

typedef enum {
	MEMCR_CHECKPOINT = 100,
	MEMCR_RESTORE
} memcr_svc_cmd;

struct service_command {
	memcr_svc_cmd cmd;
	pid_t pid;
} __attribute__((packed));

typedef enum {
	MEMCR_OK = 0,
	MEMCR_ERROR = -1
} memcr_svc_response;

struct service_response {
	memcr_svc_response resp_code;
} __attribute__((packed));

struct vm_skip_addr {
	void *addr;
	char desc;
} __attribute__((packed));

struct vm_mprotect {
	void *addr;
	unsigned long len;
	unsigned long prot;
} __attribute__((packed));

struct vm_page_addr {
	void *addr;
	char tx_page;
} __attribute__((packed));

struct vm_page {
	void *addr;
	char data[PAGE_SIZE];
#if defined(PAGE_CRC)
	uint16_t crc;
#endif
} __attribute__((packed));

struct target_context {
	pid_t pid;
	unsigned long *pc;
	unsigned long *sp;
	unsigned long *code;
	unsigned long code_size;
	unsigned long stack[16];
	uint64_t sigset;
	unsigned long *blob;
};

#endif

