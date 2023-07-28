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
#include <linux/sched.h>

static void __attribute__((used)) container(void)
{
	/*
	 * Upon completion, each blob triggers debug trap to pass the
	 * control back to the main program.
	 */

	/* rt_sigprocmask(), expects pointer to area for masks in %r15 */
	asm volatile(
		".global sigprocmask_blob			\n"
		"sigprocmask_blob:				\n"
		"movq $14, %%rax				\n" /* __NR_rt_sigprocmask */
		"movq %0, %%rdi					\n" /* @how */
		"movq %%r15, %%rsi				\n" /* @nset */
		"movq %%r15, %%rdx				\n" /* @oset */
		"movq $8, %%r10					\n" /* @sigsetsize */
		"syscall					\n"
		"int $0x03					\n"
		".global sigprocmask_blob_size			\n"
		"sigprocmask_blob_size:				\n"
		".int sigprocmask_blob_size - sigprocmask_blob	\n"
		:: "i" (SIG_SETMASK));

	/* mmaps anon area for parasite_blob */
	asm volatile(
		".global mmap_blob				\n"
		"mmap_blob:					\n"
		"movq $9, %%rax					\n" /* mmap */
		"movq $0, %%rdi					\n" /* @addr */
		"movq %%r15, %%rsi				\n" /* @len */
		"movq %0, %%rdx					\n" /* @prot */
		"movq %1, %%r10					\n" /* @flags */
		"movq $-1, %%r8					\n" /* @fd */
		"movq $0, %%r9					\n" /* @off */
		"syscall					\n"
		"int $0x03					\n"
		".global mmap_blob_size				\n"
		"mmap_blob_size:				\n"
		".int mmap_blob_size - mmap_blob		\n"
		:: "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		   "i" (MAP_ANONYMOUS | MAP_PRIVATE));

	/* clones parasite, expects parasite address in %r15 */
	asm volatile(
		".global clone_blob				\n"
		"clone_blob:					\n"
		"movq $56, %%rax				\n" /* clone */
		"movq %0, %%rdi					\n" /* @flags */
		"movq $0, %%rsi					\n" /* @newsp */
		"movq $0, %%rdx					\n" /* @parent_tid */
		"movq $0, %%r10					\n" /* @child_tid */
		"syscall					\n"
		"test %%rax, %%rax				\n"
		"jnz 1f						\n"
		"jmp *%%r15					\n" /* jmp parasite */
		"1: int $0x03					\n"
		".global clone_blob_size			\n"
		"clone_blob_size:				\n"
		".int clone_blob_size - clone_blob		\n"
		:: "i" (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM));

	/* munmaps anon area for parasite_blob, expects mmap address in %r15 and len in %r14 */
	asm volatile(
		".global munmap_blob				\n"
		"munmap_blob:					\n"
		"movq $11, %%rax				\n" /* munmap */
		"movq %%r15, %%rdi				\n" /* @addr */
		"movq %%r14, %%rsi				\n" /* @len */
		"syscall					\n"
		"int $0x03					\n"
		".global munmap_blob_size			\n"
		"munmap_blob_size:				\n"
		".int munmap_blob_size - munmap_blob		\n"
		::
	);
}