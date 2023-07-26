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

#include <stdio.h>
#include <sys/user.h>
#include <assert.h>

#include "../cpu.h"

void set_cpu_regs(struct registers *regs, unsigned long *pc, unsigned long arg0, unsigned long arg1)
{
	regs->orig_rax = -1;			/* avoid end-of-syscall processing */
	regs->rip = (unsigned long)pc;		/* point to the injected blob */
	regs->r15 = arg0;			/* r15 used as parameter to blob */
	regs->r14 = arg1;			/* r14 used as parameter to blob */
}

void *get_cpu_regs_sp(struct registers *regs)
{
	return (void *)regs->rsp;
}

void *get_cpu_regs_pc(struct registers *regs)
{
	return (void *)regs->rip;
}

unsigned long get_cpu_syscall_ret(struct registers *regs)
{
	return regs->rax;
}

unsigned long get_cpu_syscall_arg0(struct registers *regs)
{
	return regs->r15;
}

void print_cpu_regs(struct registers *regs)
{
	int idx;
	const char *rg_names[] = {
		"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
		"r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_ax",
		"rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
		"es", "fs", "gs"
	};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->rax); idx++) {
		fprintf(stdout, "regs[%s]\t %0*lx\n", rg_names[idx], 2 * (int)sizeof(unsigned long), ((unsigned long *)regs)[idx]);
	}
}

static_assert(sizeof(struct registers) == sizeof(struct user_regs_struct), "struct registers size mismatch");
