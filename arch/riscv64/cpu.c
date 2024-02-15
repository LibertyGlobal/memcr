/*
 * Copyright (C) 2023 Mariusz Kozłowski
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
	regs->s6 = arg0;			/* s6 used as arg0 to blob */
	regs->s7 = arg1;			/* s7 used as arg1 to blob */
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
	return regs->a0;
}

#if 0
unsigned long get_cpu_syscall_arg0(struct registers *regs)
{
	return regs->x10;
}
#endif

void print_cpu_regs(struct registers *regs)
{
	int idx;
	const char *rg_names[] = {
		"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
		"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
		"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
		"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
	};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->pc); idx++) {
		fprintf(stdout, "regs[%s]\t %0*lx\n", rg_names[idx], 2 * (int)sizeof(unsigned long), ((unsigned long *)regs)[idx]);
	}
}

static_assert(sizeof(struct registers) == sizeof(struct user_regs_struct), "struct registers size mismatch");
