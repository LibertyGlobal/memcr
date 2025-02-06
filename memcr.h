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
#include <assert.h>

#ifndef GIT_VERSION
#define GIT_VERSION "unknown"
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct parasite_args {
	struct sockaddr_un addr;
	char padding[2];
};

/* size must be CPU word aligned for ptrace() peek/poke */
static_assert(sizeof(struct parasite_args) % sizeof(unsigned long) == 0, "invalid size");

typedef enum {
	CMD_MPROTECT = 1,
	CMD_GET_PAGES,
	CMD_SET_PAGES,
	CMD_END,
} memcr_cmd;

struct vm_mprotect {
	unsigned long addr;
	size_t len;
	unsigned long prot;
} __attribute__((packed));

struct vm_region {
	unsigned long addr;
	unsigned long len;
};

#define VM_REGION_TX 0x01

struct vm_region_req {
	struct vm_region vmr;
	char flags;
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

