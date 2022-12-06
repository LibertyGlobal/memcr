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

#define PARASITE_STACK_SIZE 16384
#define PARASITE_ARG_SIZE   4096

.section .head.text, "ax"
	.global __parasite_head_start;
	.align 8, 0x90; /* nop */

__parasite_head_start:
	leaq __parasite_stack(%rip), %rsp
	subq $16, %rsp
	andq $~15, %rsp
	pushq $0
	movq %rsp, %rbp
	movl __parasite_cmd(%rip), %edi
	leaq __parasite_args(%rip), %rsi
	call service
	int $0x03 /* SIGTRAP */
	.align 8, 0x90

__parasite_cmd:
	.long 0

__parasite_args:
	.long 0
	.space PARASITE_ARG_SIZE, 0
	.space PARASITE_STACK_SIZE, 0

__parasite_stack:
	.long 0
