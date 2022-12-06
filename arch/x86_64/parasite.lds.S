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

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.blob 0x0 : {
		*(.head.text)
		*(.text*)
		. = ALIGN(32);
		*(.data*)
		. = ALIGN(32);
		*(.rodata*)
		. = ALIGN(32);
		*(.bss*)
		. = ALIGN(32);
	} =0x00000000

	/DISCARD/ : {
		*(.debug*)
		*(.comment*)
		*(.note*)
		*(.group*)
		*(.eh_frame*)
		*(*)
	}
}
