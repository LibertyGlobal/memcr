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

#ifndef __CPU_H__
#define __CPU_H__

#if defined(__x86_64__)
#include "x86_64/cpu.h"
#elif defined(__arm__)
#include "arm/cpu.h"
#elif defined(__aarch64__)
#include "arm64/cpu.h"
#elif defined(__riscv_xlen)
#include "riscv64/cpu.h"
#else
#error unsupported arch
#endif

void set_cpu_regs(struct registers *regs, unsigned long *pc, unsigned long arg0, unsigned long arg1);
void *get_cpu_regs_sp(struct registers *regs);
void *get_cpu_regs_pc(struct registers *regs);
unsigned long get_cpu_syscall_ret(struct registers *regs);
unsigned long get_cpu_syscall_arg0(struct registers *regs);
void print_cpu_regs(struct registers *regs);

#endif