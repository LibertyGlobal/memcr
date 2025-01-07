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

#ifndef __LINUX_ABI_X86_64_H__
#define __LINUX_ABI_X86_64_H__

static long syscall0(int nr)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr)
		     : "memory");
	return ret;
}

static long syscall1(int nr, unsigned long arg0)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "memory");
	return ret;
}

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "memory");
	return ret;
}

static long syscall3(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long syscall4(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	register unsigned long r10 asm("r10") = r10;
	long ret;

	r10 = arg3;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long syscall5(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	long ret;

	r10 = arg3;
	r8 = arg4;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

#if 0
static long syscall6(int nr, unsigned long arg0, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	register unsigned long r9 asm("r9") = r9;
	long ret;

	r10 = arg3;
	r8 = arg4;
	r9 = arg5;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}
#endif

#endif
