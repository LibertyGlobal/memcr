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

#include <signal.h>
#include <sys/mman.h>
#include <linux/sched.h>

static void __attribute__((used)) container(void)
{
	/*
	 * Upon completion, each blob triggers debug trap to pass the
	 * control back to the main program.
	 */

	/* this one just says hi to stdout for testing blob execution */
	asm volatile(
		".global test_blob				\n"
		"test_blob:					\n"
		"mov x8, #64					\n" /* __NR_write */
		"mov x0, #1					\n" /* @fd */
		"adr x1, _string				\n" /* @buf */
		"mov x2, #20					\n" /* @count */
		"svc #0						\n"
		"brk #0						\n" /* SIGTRAP */
		"_string: .ascii \"BLOB: hello, world!\\n\"	\n"
		".global test_blob_size				\n"
		"test_blob_size:				\n"
		".int test_blob_size - test_blob		\n"
	);

	/* rt_sigprocmask(), expects pointer to area for masks in x10 */
	asm volatile(
		".global sigprocmask_blob			\n"
		"sigprocmask_blob:				\n"
		"mov x8, #135					\n" /* __NR_rt_sigprocmask */
		"mov x0, %0					\n" /* @how */
		"mov x1, x10					\n" /* @nset */
		"add x2, x10, #8				\n" /* @oset */
		"mov x11, x2					\n"
		"mov x3, #8					\n" /* @sigsetsize */
		"svc #0						\n"
		"ldr x8, [x11]					\n"
		"brk #0						\n" /* SIGTRAP */
		".global sigprocmask_blob_size			\n"
		"sigprocmask_blob_size:				\n"
		".int sigprocmask_blob_size - sigprocmask_blob	\n"
		:: "i" (SIG_SETMASK)
	);

	/* mmaps anon area for parasite_blob */
	asm volatile(
		".global mmap_blob				\n"
		"mmap_blob:					\n"
		"mov x8, #222					\n" /* __NR_mmap2 */
		"mov x0, #0					\n" /* @addr */
		"mov x1, x10					\n" /* @len */
		"mov x2, %0					\n" /* @prot */
		"mov x3, %1					\n" /* @flags */
		"ldr x4, =-1					\n" /* @fd */
		"mov x5, #0					\n" /* @off */
		"svc #0						\n"
		"brk #0						\n" /* SIGTRAP */
		".global mmap_blob_size				\n"
		"mmap_blob_size:				\n"
		".int mmap_blob_size - mmap_blob		\n"
		:: "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		   "i" (MAP_ANONYMOUS | MAP_PRIVATE)
	);

	/* clones parasite, expects parasite address in x10 */
	asm volatile(
		".global clone_blob				\n"
		"clone_blob:					\n"
		"mov x8, #220					\n" /* __NR_clone */
		"ldr x0, CLONE_FLAGS				\n" /* @flags */
		"mov x1, #0					\n" /* @newsp */
		"mov x2, #0					\n" /* @parent_tid */
		"mov x3, #0					\n" /* @child_tid */
		"svc #0						\n"
		"cmp x0, #0					\n"
		"beq .child					\n"
		"brk #0						\n" /* SIGTRAP */
		".child:					\n"
		"br x10						\n" /* br parasite */
		"CLONE_FLAGS:					\n"
		".quad (%0 & 0xffffffff)			\n" /* zero high .word */
		".global clone_blob_size			\n"
		"clone_blob_size:				\n"
		".int clone_blob_size - clone_blob		\n"
		:: "i" (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM | CLONE_PTRACE)
	);

	/* munmap anon area for parasite_blob, expects addr in x10 and len in x11 */
	asm volatile(
		".global munmap_blob				\n"
		"munmap_blob:					\n"
		"mov x8, #215					\n" /* __NR_munmap */
		"mov x0, x10					\n" /* @addr */
		"mov x1, x11					\n" /* @len */
		"svc #0						\n"
		"brk #0						\n" /* SIGTRAP */
		".global munmap_blob_size			\n"
		"munmap_blob_size:				\n"
		".int munmap_blob_size - munmap_blob		\n"
	);
}
