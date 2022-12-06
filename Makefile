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

CFLAGS = -Wall -g

ifeq ("$(origin O)", "command line")
    GCC_O = $(O)
endif
ifndef GCC_O
    GCC_O = 0
endif

ifeq ($(GCC_O),1)
    CFLAGS += -O2
else
    CFLAGS += -O0
    CFLAGS += -fstack-protector-all -fstack-protector-strong
endif

ARCH ?= x86_64

ifeq ($(ARCH), x86_64)
    CC = gcc
    LD = ld
    OBJCOPY = objcopy
    LDARCH = i386:x86-64
    HSARCH = x86-64
else ifeq ($(ARCH), arm)
    CC = arm-rdk-linux-gnueabi-gcc
    LD = arm-rdk-linux-gnueabi-ld.bfd
    OBJCOPY = arm-rdk-linux-gnueabi-objcopy
    SYSROOT = --sysroot=$(SYSROOT_DIR)
    LDARCH = arm
    HSARCH = arm
else
    $(error unsupported arch "$(ARCH)")
endif

CFLAGS += $(SYSROOT)
GOFF = ./gen-offsets.sh

B ?= .


all: $(B)/memcr

$(B)/parasite-head.o: arch/$(ARCH)/parasite-head.S
	$(CC) -Wall -Wstrict-prototypes -O0 -fno-stack-protector -fpie -nostdlib -fomit-frame-pointer -Wa,--noexecstack $(SYSROOT) -c $< -o $@

$(B)/syscall.o: arch/syscall.c arch/$(ARCH)/linux-abi.h
	$(CC) -Wall -Wstrict-prototypes -O0 -fno-stack-protector -fpie -nostdlib -fomit-frame-pointer -Wa,--noexecstack $(SYSROOT) -c $< -o $@

$(B)/parasite.o: parasite.c memcr.h arch/syscall.h
	$(CC) -Wall -Wstrict-prototypes -O2 -fno-stack-protector -fpie -nostdlib -fomit-frame-pointer -Wa,--noexecstack $(SYSROOT) -c $< -o $@

$(B)/parasite.bin.o: $(B)/parasite-head.o $(B)/syscall.o $(B)/parasite.o arch/$(ARCH)/parasite.lds.S
	$(LD) -T arch/$(ARCH)/parasite.lds.S -o $@ $(B)/parasite-head.o $(B)/syscall.o $(B)/parasite.o

$(B)/parasite.bin: $(B)/parasite.bin.o
	$(OBJCOPY) -O binary $< $@

$(B)/parasite-blob.h: $(B)/parasite.bin arch/$(ARCH)/parasite.lds.S
	$(GOFF) parasite $(B) > $@

$(B)/enter.o: arch/$(ARCH)/enter.c
	$(CC) $(CFLAGS) -c $< -o $@

$(B)/cpu.o: arch/$(ARCH)/cpu.c
	$(CC) $(CFLAGS) -c $^ -o $@

$(B)/memcr.o: memcr.c $(B)/parasite-blob.h
	$(CC) $(CFLAGS) -I$(B) -c $< -o $@

$(B)/memcr: $(B)/memcr.o $(B)/cpu.o $(B)/enter.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(B)/*.o $(B)/*.s $(B)/*.bin $(B)/parasite-blob.h $(B)/memcr

.PHONY: all clean
