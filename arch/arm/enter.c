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

#include <signal.h>
#include <sys/mman.h>

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
		"mov r7, #4					\n" /* __NR_write */
		"mov r0, #1					\n" /* @fd */
		"adr r1, _string				\n" /* @buf */
		"mov r2, #20					\n" /* @count */
		"svc 0						\n"
		"udf #16					\n" /* SIGTRAP */
		"_string: .ascii \"BLOB: hello, world!\\n\"	\n"
		".global test_blob_size				\n"
		"test_blob_size:				\n"
		".int test_blob_size - test_blob		\n"
	);

	/* rt_sigprocmask(), expects pointer to area for masks in r8 */
	asm volatile(
		".global sigprocmask_blob			\n"
		"sigprocmask_blob:				\n"
		"mov r7, #175					\n" /* __NR_rt_sigprocmask */
		"mov r0, %0					\n" /* @how */
		"mov r1, r8					\n" /* @nset */
		"add r2, r8, #8					\n" /* @oset */
		"mov r9, r2					\n"
		"mov r3, #8					\n" /* @sigsetsize */
		"svc 0x0					\n"
		"ldr r8, [r9]					\n"
		"udf #16					\n" /* SIGTRAP */
		".global sigprocmask_blob_size			\n"
		"sigprocmask_blob_size:				\n"
		".int sigprocmask_blob_size - sigprocmask_blob	\n"
		:: "i" (SIG_SETMASK)
	);

	/* mmaps anon area for parasite_blob */
	asm volatile(
		".global mmap_blob				\n"
		"mmap_blob:					\n"
		"mov r7, #192					\n" /* __NR_mmap2 */
		"mov r0, #0					\n" /* @addr */
		"mov r1, r8					\n" /* @len */
		"mov r2, %0					\n" /* @prot */
		"mov r3, %1					\n" /* @flags */
		"ldr r4, =-1					\n" /* @fd */ // TODO mov r4, #-1 vs ldr r4, =-1
		"mov r5, #0					\n" /* @off */
		"svc 0x0					\n"
		"udf #16					\n" /* SIGTRAP */
		".global mmap_blob_size				\n"
		"mmap_blob_size:				\n"
		".int mmap_blob_size - mmap_blob		\n"
		:: "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		   "i" (MAP_ANONYMOUS | MAP_PRIVATE)
	);

	/* clones parasite, expects parasite address in r8 */
	asm volatile(
		".global clone_blob				\n"
		"clone_blob:					\n"
		"mov r7, #120					\n" /* __NR_clone */
		"movw r0, #0x2f00				\n" /* r0 = (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM | CLONE_PTRACE) */
		"movt r0, #0x8005				\n"
		"mov r1, #0					\n" /* @newsp */
		"mov r2, #0					\n" /* @parent_tid */
		"mov r3, #0					\n" /* @child_tid */
		"svc 0x0					\n"
		"cmp r0, #0					\n"
		"bxeq r8					\n" /* bx parasite */
		"udf #16					\n" /* SIGTRAP */
		".global clone_blob_size			\n"
		"clone_blob_size:				\n"
		".int clone_blob_size - clone_blob		\n"
	);

	/* munmap anon area for parasite_blob, expects addr in r8 and len in r9 */
	asm volatile(
		".global munmap_blob				\n"
		"munmap_blob:					\n"
		"mov r7, #91					\n" /* __NR_munmap */
		"mov r0, r8					\n" /* @addr */
		"mov r1, r9					\n" /* @len */
		"svc 0x0					\n"
		"udf #16					\n" /* SIGTRAP */
		".global munmap_blob_size			\n"
		"munmap_blob_size:				\n"
		".int munmap_blob_size - munmap_blob		\n"
	);
}
