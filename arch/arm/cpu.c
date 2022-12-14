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

#include "cpu.h"

void set_cpu_regs(struct user_regs_struct *uregs, unsigned long *pc, unsigned long arg0, unsigned long arg1)
{
	uregs->orig_r0 = -1;			/* avoid end-of-syscall processing */
	uregs->pc = (unsigned long )pc;		/* point to the injected blob */
	uregs->r8 = arg0;			/* r8 used as arg0 to blob */
	uregs->r9 = arg1;			/* r9 used as arg1 to blob */

	/* Make sure flags are in known state */
	uregs->cpsr &= PSR_f | PSR_s | PSR_x | MODE32_BIT;
}

void *get_cpu_regs_sp(struct user_regs_struct *uregs)
{
	return (void *)uregs->sp;
}

void *get_cpu_regs_pc(struct user_regs_struct *uregs)
{
	return (void *)uregs->pc;
}

unsigned long get_cpu_syscall_ret(struct user_regs_struct *uregs)
{
	return uregs->r0;
}

unsigned long get_cpu_syscall_arg0(struct user_regs_struct *uregs)
{
	return uregs->r8;
}

void print_cpu_regs(struct user_regs_struct *regs)
{
	int idx;
	const char *rg_names[] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc", "cpsr", "orig_r0"};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->r0); idx++) {
		fprintf(stdout, "regs[%s]%s %08lx\n", rg_names[idx], sizeof(rg_names[idx]) > 4 ? "" : "\t", ((unsigned long *)regs)[idx]);
	}
}
