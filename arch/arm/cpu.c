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
#include <linux/ptrace.h>
#include <sys/user.h>
#include <assert.h>

#include "cpu.h"

void set_cpu_regs(struct registers *regs, unsigned long *pc, unsigned long arg0, unsigned long arg1)
{
	regs->orig_r0 = -1;			/* avoid end-of-syscall processing */
	regs->pc = (unsigned long)pc;		/* point to the injected blob */
	regs->r8 = arg0;			/* r8 used as arg0 to blob */
	regs->r9 = arg1;			/* r9 used as arg1 to blob */

	/* Make sure flags are in known state */
	regs->cpsr &= PSR_f | PSR_s | PSR_x | MODE32_BIT;
}

void *get_cpu_regs_sp(struct registers *regs)
{
	return (void *)regs->sp;
}

void *get_cpu_regs_pc(struct registers *regs)
{
	return (void *)regs->pc;
}

unsigned long get_cpu_syscall_ret(struct registers *regs)
{
	return regs->r0;
}

unsigned long get_cpu_syscall_arg0(struct registers *regs)
{
	return regs->r8;
}

void print_cpu_regs(struct registers *regs)
{
	int idx;
	const char *rg_names[] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc",
		"cpsr", "orig_r0"
	};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->r0); idx++) {
		fprintf(stdout, "regs[%s]\t %0*lx\n", rg_names[idx], 2 * (int)sizeof(unsigned long), ((unsigned long *)regs)[idx]);
	}
}

static_assert(sizeof(struct registers) == sizeof(struct user_regs), "struct registers size mismatch");
