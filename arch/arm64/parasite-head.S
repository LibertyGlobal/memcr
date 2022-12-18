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

#define PARASITE_STACK_SIZE 16384
#define PARASITE_ARG_SIZE   4096

.section .head.text, "ax"
	.globl __parasite_head_start
	.align 4, 0x00

__parasite_head_start:
	adr x1, __parasite_stack
	mov sp, x1
	adr x0, __parasite_cmd
	ldr x0, [x0]
	adr x1, __parasite_args
	bl service
	brk #0 /* SIGTRAP */
	.align 4, 0x00

__parasite_cmd:
	.quad 0

__parasite_args:
	.quad 0
	.space PARASITE_ARG_SIZE, 0
	.space PARASITE_STACK_SIZE, 0
	.space 224, 0 /* 8+4 fill */

__parasite_stack:
	.quad 0
