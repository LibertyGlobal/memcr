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

#ifndef __LINUX_ABI_ARM_H__
#define __LINUX_ABI_ARM_H__

static long syscall0(int nr)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0");
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7)
		     : "memory");
	return r0;
}

static long syscall1(int nr, unsigned long arg0)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0)
		     : "memory");
	return r0;
}

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	register long r1 asm("r1") = arg1;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0), "r" (r1)
		     : "memory");
	return r0;
}

static long syscall3(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	register long r1 asm("r1") = arg1;
	register long r2 asm("r2") = arg2;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0), "r" (r1), "r" (r2)
		     : "memory");
	return r0;
}

static long syscall4(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	register long r1 asm("r1") = arg1;
	register long r2 asm("r2") = arg2;
	register long r3 asm("r3") = arg3;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0), "r" (r1), "r" (r2), "r" (r3)
		     : "memory");
	return r0;
}

static long syscall5(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	register long r1 asm("r1") = arg1;
	register long r2 asm("r2") = arg2;
	register long r3 asm("r3") = arg3;
	register long r4 asm("r4") = arg4;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4)
		     : "memory");
	return r0;
}

#if 0
static long syscall6(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	register long r7 asm("r7") = nr;
	register long r0 asm("r0") = arg0;
	register long r1 asm("r1") = arg1;
	register long r2 asm("r2") = arg2;
	register long r3 asm("r3") = arg3;
	register long r4 asm("r4") = arg4;
	register long r5 asm("r5") = arg5;
	asm volatile("svc 0"
		     : "=r" (r0)
		     : "r" (r7), "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4), "r" (r5)
		     : "memory");
	return r0;
}
#endif

#endif
