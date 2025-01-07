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

#ifndef __LINUX_ABI_RISCV64_H__
#define __LINUX_ABI_RISCV64_H__

static long syscall0(int nr)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0");
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7)
		     : "memory");
	return a0;
}

static long syscall1(int nr, unsigned long arg0)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0)
		     : "memory");
	return a0;
}

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0), "r" (a1)
		     : "memory");
	return a0;
}

static long syscall3(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long a2 asm("a2") = arg2;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0), "r" (a1), "r" (a2)
		     : "memory");
	return a0;
}

static long syscall4(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long a2 asm("a2") = arg2;
	register long a3 asm("a3") = arg3;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0), "r" (a1), "r" (a2), "r" (a3)
		     : "memory");
	return a0;
}

static long syscall5(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long a2 asm("a2") = arg2;
	register long a3 asm("a3") = arg3;
	register long a4 asm("a4") = arg4;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0), "r" (a1), "r" (a2), "r" (a3), "r" (a4)
		     : "memory");
	return a0;
}

#if 0
static long syscall6(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	register long a7 asm("a7") = nr;
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long a2 asm("a2") = arg2;
	register long a3 asm("a3") = arg3;
	register long a4 asm("a4") = arg4;
	register long a5 asm("a5") = arg5;
	asm volatile("ecall"
		     : "=r" (a0)
		     : "r" (a7), "r" (a0), "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5)
		     : "memory");
	return a0;
}
#endif

#endif
