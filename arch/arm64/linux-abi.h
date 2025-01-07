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

#ifndef __LINUX_ABI_ARM64_H__
#define __LINUX_ABI_ARM64_H__

static long syscall0(int nr)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0");
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8)
		     : "memory");
	return x0;
}

static long syscall1(int nr, unsigned long arg0)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0)
		     : "memory");
	return x0;
}

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	register long x1 asm("x1") = arg1;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0), "r" (x1)
		     : "memory");
	return x0;
}

static long syscall3(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	register long x1 asm("x1") = arg1;
	register long x2 asm("x2") = arg2;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0), "r" (x1), "r" (x2)
		     : "memory");
	return x0;
}

static long syscall4(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	register long x1 asm("x1") = arg1;
	register long x2 asm("x2") = arg2;
	register long x3 asm("x3") = arg3;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0), "r" (x1), "r" (x2), "r" (x3)
		     : "memory");
	return x0;
}

static long syscall5(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	register long x1 asm("x1") = arg1;
	register long x2 asm("x2") = arg2;
	register long x3 asm("x3") = arg3;
	register long x4 asm("x4") = arg4;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0), "r" (x1), "r" (x2), "r" (x3), "r" (x4)
		     : "memory");
	return x0;
}

#if 0
static long syscall6(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = arg0;
	register long x1 asm("x1") = arg1;
	register long x2 asm("x2") = arg2;
	register long x3 asm("x3") = arg3;
	register long x4 asm("x4") = arg4;
	register long x5 asm("x5") = arg5;
	asm volatile("svc #0"
		     : "=r" (x0)
		     : "r" (x8), "r" (x0), "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5)
		     : "memory");
	return x0;
}
#endif

#endif
