/*
 * Copyright (C) 2022 Mariusz Kozłowski
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

#include "../cpu.h"

void set_cpu_regs(struct registers *regs, unsigned long *pc, unsigned long arg0, unsigned long arg1)
{
	regs->pc = (unsigned long)pc;		/* point to the injected blob */
	regs->x10 = arg0;			/* x10 used as arg0 to blob */
	regs->x11 = arg1;			/* x11 used as arg1 to blob */

	/* Make sure flags are in known state */
	regs->pstate &= PSR_f | PSR_s | PSR_x | PSR_MODE32_BIT;
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
	return regs->x0;
}

unsigned long get_cpu_syscall_arg0(struct registers *regs)
{
	return regs->x10;
}

void print_cpu_regs(struct registers *regs)
{
	int idx;
	const char *rg_names[] = {
		"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		"x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
		"pc", "pstate"
	};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->x0); idx++) {
		fprintf(stdout, "regs[%s]\t %0*lx\n", rg_names[idx], 2 * (int)sizeof(unsigned long), ((unsigned long *)regs)[idx]);
	}
}

static_assert(sizeof(struct registers) == sizeof(struct user_regs_struct), "struct registers size mismatch");