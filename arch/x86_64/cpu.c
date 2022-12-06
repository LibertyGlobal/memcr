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

#include "cpu.h"

void set_cpu_regs(struct user_regs_struct *uregs, unsigned long *pc, unsigned long arg0, unsigned long arg1)
{
	uregs->orig_rax = -1;				/* avoid end-of-syscall processing */
	uregs->rip = (unsigned long )pc;	/* point to the injected blob */
	uregs->r15 = arg0;					/* r15 used as parameter to blob */
	uregs->r14 = arg1;					/* r14 used as parameter to blob */
}

void *get_cpu_regs_sp(struct user_regs_struct *uregs)
{
	return (void *)uregs->rsp;
}

void *get_cpu_regs_pc(struct user_regs_struct *uregs)
{
	return (void *)uregs->rip;
}

unsigned long get_cpu_syscall_ret(struct user_regs_struct *uregs)
{
	return uregs->rax;
}

unsigned long get_cpu_syscall_arg0(struct user_regs_struct *uregs)
{
	return uregs->r15;
}

void print_cpu_regs(struct user_regs_struct *regs)
{
	int idx;

	const char *rg_names[] = {"r15", "r14", "r13", "r12", "bp", "bx", "r11", "r10", "r9", "r8", "ax", "cx", "dx", "si", "di", "orig_ax", "ip", "cs", "flags", "sp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"};

	for (idx = 0; idx < sizeof(*regs)/sizeof(regs->rax); idx++) {
		fprintf(stdout, "regs[%s]%s %016lx\n", rg_names[idx], sizeof(rg_names[idx]) > 4 ? "\t" : "\t\t", ((unsigned long *)regs)[idx]);
	}
}