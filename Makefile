#
# Copyright (C) 2022 Liberty Global Service B.V.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, version 2
# of the license.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#

MAKEFLAGS += -rR

ifeq ("$(origin CC)", "default")
    undefine CC
endif
ifeq ("$(origin LD)", "default")
    undefine LD
endif

CFLAGS = -Wall -Werror
# memcr CFLAGS
MCFLAGS = $(CFLAGS) -g
# parasite CFLAGS
PCFLAGS = $(CFLAGS)

ifeq ("$(origin O)", "command line")
    GCC_O = $(O)
endif
ifndef GCC_O
    GCC_O = 0
endif

ifeq ($(GCC_O), 1)
    MCFLAGS += -O2
else
    MCFLAGS += -O0
    MCFLAGS += -fstack-protector-all -fstack-protector-strong
endif

CC ?= $(CROSS_COMPILE)gcc
LD ?= $(CROSS_COMPILE)ld.bfd
OBJCOPY ?= $(CROSS_COMPILE)objcopy

ifeq ($(shell $(LD) -v | grep "GNU ld"),)
    LD := $(LD:-ld=-ld.bfd)
endif

ifndef ARCH
    # try to detect the target architecture
    GCC_TARGET=$(shell $(CC) -dumpmachine)
    ifeq ($(findstring x86_64, $(GCC_TARGET)), x86_64)
        ARCH = x86_64
    else ifeq ($(findstring arm, $(GCC_TARGET)), arm)
        ARCH = arm
    else ifeq ($(findstring aarch64, $(GCC_TARGET)), aarch64)
        ARCH = arm64
    else
        $(error unable to detect arch: $(GCC_TARGET))
    endif
endif

ifeq ($(ARCH), x86_64)
    # do nothing
else ifeq ($(ARCH), arm)
    MCFLAGS += -marm
    PCFLAGS += -marm
else ifeq ($(ARCH), arm64)
    # do nothing
else
    $(error unsupported arch: $(ARCH))
endif

PCFLAGS = -Wstrict-prototypes -fno-stack-protector -fpie -nostdlib -ffreestanding -fomit-frame-pointer -Wa,--noexecstack

GOFF = ./gen-offsets.sh

B ?= .


all: $(B)/memcr $(B)/client

$(B)/parasite-head.o: arch/$(ARCH)/parasite-head.S
	$(CC) $(PCFLAGS) -O0 -c $< -o $@

$(B)/syscall.o: arch/syscall.c arch/$(ARCH)/linux-abi.h
	$(CC) $(PCFLAGS) -O0 -c $< -o $@

$(B)/parasite.o: parasite.c memcr.h arch/syscall.h
	$(CC) $(PCFLAGS) -O2 -c $< -o $@

$(B)/parasite.bin.o: $(B)/parasite-head.o $(B)/syscall.o $(B)/parasite.o arch/$(ARCH)/parasite.lds.S
	$(LD) -T arch/$(ARCH)/parasite.lds.S -o $@ $(B)/parasite-head.o $(B)/syscall.o $(B)/parasite.o

$(B)/parasite.bin: $(B)/parasite.bin.o
	$(OBJCOPY) -O binary $< $@

$(B)/parasite-blob.h: $(B)/parasite.bin arch/$(ARCH)/parasite.lds.S
	$(GOFF) parasite $(B) > $@

$(B)/enter.o: arch/$(ARCH)/enter.c
	$(CC) $(MCFLAGS) -c $< -o $@

$(B)/cpu.o: arch/$(ARCH)/cpu.c
	$(CC) $(MCFLAGS) -c $^ -o $@

$(B)/memcr.o: memcr.c $(B)/parasite-blob.h
	$(CC) $(MCFLAGS) -I$(B) -c $< -o $@

$(B)/memcr: $(B)/memcr.o $(B)/cpu.o $(B)/enter.o
	$(CC) $(MCFLAGS) $^ -o $@

$(B)/client.o: client.c
	$(CC) $(CFLAGS) -I$(B) -c $< -o $@

$(B)/client: $(B)/client.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(B)/*.o $(B)/*.s $(B)/*.bin $(B)/parasite-blob.h $(B)/memcr $(B)/client

.PHONY: all clean
