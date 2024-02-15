/*
 * Copyright (C) 2023 Mariusz Kozłowski
 * Copyright (C) 2024 Wojciech Łazarski
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

#include <string.h>


static void __attribute__((used)) container(void)
{
	/*
	 * Upon completion, each blob triggers debug trap to pass the
	 * control back to the main program.
	 */

	/* rt_sigprocmask(), expects pointer to area for masks in a6 */

	asm volatile(
		".global sigprocmask_blob			\n"
		".align 3					\n"
		"sigprocmask_blob:				\n"
		"li a7, 135					\n" /* __NR_rt_sigprocmask */
		"li a0, %0					\n" /* @how */
		"mv a1, s6					\n" /* @nset */
		"mv a2, s6					\n" /* @oset */
		"li a3, 8					\n" /* @sigsetsize */
		"ecall						\n"
		"ebreak						\n" /* SIGTRAP */
		".global sigprocmask_blob_size			\n"
		".align 3					\n"
		"sigprocmask_blob_size:				\n"
		".int sigprocmask_blob_size - sigprocmask_blob	\n"
		:: "i" (SIG_SETMASK)
	);

	/* mmaps anon area for parasite_blob */
	asm volatile(
		".global mmap_blob				\n"
		".align 3					\n"
		"mmap_blob:					\n"
		"li a7, 222					\n" /* __NR_mmap2 */
		"li a0, 0					\n" /* @addr */
		"mv a1, s6					\n" /* @len */
		"li a2, %0					\n" /* @prot */
		"li a3, %1					\n" /* @flags */
		"li a4, -1					\n" /* @fd */
		"li a5, 0					\n" /* @off */
		"ecall						\n"
		"ebreak						\n" /* SIGTRAP */
		".global mmap_blob_size				\n"

		".align 3					\n"
		"mmap_blob_size:				\n"
		".int mmap_blob_size - mmap_blob		\n"
		:: "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		   "i" (MAP_ANONYMOUS | MAP_PRIVATE)
	);

	/* clones parasite, expects parasite address in a6 */
	asm volatile(
		".global clone_blob				\n"
		".align 3					\n"
		"clone_blob:					\n"
		"li a7, 220					\n" /* __NR_clone */
		"ld a0, CLONE_FLAGS				\n" /* @flags */
		"li a1, 0					\n" /* @newsp */
		"li a2, 0					\n" /* @parent_tid */
		"li a3, 0					\n" /* @child_tid */
		"ecall						\n"
		"li a1, 0					\n"
		"beq a0, a1, .child				\n"
		"ebreak						\n" /* SIGTRAP */
		".child:					\n"
		"jr s6						\n" /* br parasite */
		"CLONE_FLAGS:					\n"
		".quad (%0 & 0xffffffff)			\n" /* zero high .word */
		".global clone_blob_size			\n"
		"clone_blob_size:				\n"

		".align 3					\n"
		".int clone_blob_size - clone_blob		\n"
		:: "i" (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM)
	);

	/* munmap anon area for parasite_blob, expects addr in a6 and len in a7 */
	asm volatile(
		".global munmap_blob				\n"
		".align 3					\n"
		"munmap_blob:					\n"
		"li a7, 215					\n" /* __NR_munmap */
		"mv a0, s6					\n" /* @addr */
		"mv a1, s7					\n" /* @len */
		"ecall						\n"
		"ebreak						\n" /* SIGTRAP */
		".global munmap_blob_size			\n"

		".align 3					\n"
		"munmap_blob_size:				\n"
		".int munmap_blob_size - munmap_blob		\n"
	);
}
