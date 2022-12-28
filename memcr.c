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

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <dirent.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <sys/param.h> /* MIN(), MAX() */

#include "memcr.h"
#include "arch/cpu.h"
#include "arch/enter.h"
#include "parasite-blob.h"

#define NT_PRSTATUS 1

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define PARASITE_CMD_ADDR(start)	(((char *)start) + parasite_blob_offset__parasite_cmd)
#define PARASITE_ARGS_ADDR(start)	(((char *)start) + parasite_blob_offset__parasite_args)

#define __DEBUG__ fprintf(stderr, "%s: %s() +%d\n", __FILE__, __func__, __LINE__);


#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_EXEC	0x4

#define FLAG_NONE	0x0
#define FLAG_STACK	0x1		/* stack */
#define FLAG_HEAP	0x2		/* heap */
#define FLAG_ANON 	0x3		/* anonymous mapping */
#define FLAG_FILE	0x4		/* file mapped area */

struct vm_area {
	unsigned long start;
	unsigned long end;
	unsigned long prot;
	unsigned long flags;
};

static char *dump_dir;
static char *socket_dir;
static int nowait;
static int finish = 0;

#define PATH_MAX        4096	/* # chars in a path name including nul */
#define MAX_THREADS		1024

static pid_t tids[MAX_THREADS];
static int nr_threads;

#define MAX_SKIP_ADDR	1024
static struct vm_skip_addr skip_addr[MAX_SKIP_ADDR];

#define MAX_VMAS		4096
static struct vm_area vmas[MAX_VMAS];
static int nr_vmas;

static pid_t parasite_pid;
static struct target_context ctx;

static int interrupted;

/*
 * man sigaction: For a ptrace(2) event, si_code will contain SIG‐TRAP and have the ptrace event in the high byte:
 * (SIGTRAP | PTRACE_EVENT_foo << 8).
 */
#define SI_EVENT(si_code)	(((si_code) & 0xFF00) >> 8)

static int iterate_pstree(pid_t pid, int skip_self, int max_threads, int (*callback)(pid_t pid))
{
	int ret;
	char path[PATH_MAX];
	DIR *task_dir;
	struct dirent *ent;
	int nr_threads = 0;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	task_dir = opendir(path);
	if (!task_dir) {
		fprintf(stderr, "opendir() %s: %m\n", path);
		return -errno;
	}

	while ((ent = readdir(task_dir))) {
		pid_t tid;
		char *eptr;

		tid = strtoul(ent->d_name, &eptr, 0);
		if (*eptr != '\0')
			continue;

		if (nr_threads >= max_threads) {
			fprintf(stderr, "too many threads\n");
			return -EINVAL;
		}

		if (skip_self && tid == pid) {
			printf("skip tid %d == pid %d\n", tid, pid);
			continue;
		}

		ret = callback(tid);
		if (ret)
			break;
	}

	closedir(task_dir);
	return ret;
}

static int seize_pid(pid_t pid)
{
	int ret;
	int status;
	siginfo_t si;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		fprintf(stderr, "ptrace(PTRACE_SEIZE) pid %d: %m\n", pid);
		return 1;
	}

try_again:
	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret) {
		fprintf(stderr, "ptrace(PTRACE_INTERRUPT) pid %d: %m\n", pid);
		return 1;
	}

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		fprintf(stderr, "wait4() pid %d: %m\n", pid);
		return 1;
	}

	if (ret != pid) {
		fprintf(stderr, "wrong pid attached ret %d != pid %d\n", ret, pid);
		return 1;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "pid %d not stopped after seize, status %x\n", pid, status);
		return 1;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret) {
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) pid %d, %m\n", pid);
		return 1;
	}

	if (SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */
		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)si.si_signo);
		if (ret) {
			fprintf(stderr, "can't continue signal handling: %m\n");
			return 1;
		}

		goto try_again;
	}

	ret = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(unsigned long)PTRACE_O_TRACEEXIT);
	if (ret) {
		fprintf(stderr, "ptrace(PTRACE_SETOPTIONS) pid %d: %m\n", pid);
		return 1;
	}

	tids[nr_threads++] = pid;

	return 0;
}

static int seize_target(pid_t pid)
{
	int ret;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d", pid);

	ret = access(path, F_OK);
	if (ret) {
		fprintf(stderr, "%d: No such process\n", pid);
		return 1;
	}

	printf("[+] seizing target pid %d\n", pid);

	ret = iterate_pstree(pid, 0, MAX_THREADS, seize_pid);
	if (ret)
		return ret;

	printf("[i] %d %s\n", nr_threads, nr_threads == 1 ? "thread" : "threads");

	return 0;
}

static int unseize_pid(int pid)
{
	int ret;

	ret = ptrace(PTRACE_DETACH, pid, NULL, 0);
	if (ret < 0) {
		fprintf(stderr, "ptrace(PTRACE_DETACH) failed: %m\n");
	}

	return ret;
}

static int unseize_target(void)
{
	int ret = 0;
	int i;

	printf("[+] unseizing target\n");

	for (i = 0; i < nr_threads; i++)
		ret |= unseize_pid(tids[i]);

	return ret;
}

static inline void create_filesystem_socketname(char * addr, int addr_size, int pid)
{
	snprintf(addr, addr_size, "%s/memcr%u", socket_dir, pid);
}

static inline void create_abstract_socketname(char * addr, int addr_size, int pid)
{
	snprintf(addr, addr_size, "#memcr%u", pid);
}

static int xconnect(int pid)
{
	int cd;
	struct sockaddr_un addr = { 0 };
	int ret;
	int cnt = 0;

	cd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (cd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
		return -1;
	}

	addr.sun_family = PF_UNIX;

	if (socket_dir) {
		create_filesystem_socketname(addr.sun_path, sizeof(addr.sun_path), pid);
	} else {
		create_abstract_socketname(addr.sun_path, sizeof(addr.sun_path), pid);
		addr.sun_path[0] = '\0';
	}

	/* parasite needs some time to start listening on a socket */
retry:
	ret = connect(cd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
	if (ret < 0) {
		if (cnt++ < 100) {
			usleep(1*1000);
			goto retry;
		} else {
			fprintf(stderr, "connect() to %s failed: %m\n", addr.sun_path + 1);
			close(cd);
		}
	}

	return cd;
}

static int xread(int fd, void *buf, int size)
{
	int ret;
	int off = 0;

	assert(size != 0);

	while (1) {
		ret = read(fd, buf + off, size - off);
		if (ret == 0)
			break;

		if (ret < 0) {
			fprintf(stderr, "\n%s() failed: errno %m\n", __func__);
			break;
		}

		if (ret < size - off) {
			off += ret;
			continue;
		}

		return size;
	}

	return ret;
}

static int xwrite(int fd, void *buf, int size)
{
	int ret;
	int off = 0;

	assert(size != 0);

	while (1) {
		ret = write(fd, buf + off, size - off);
		if (ret < 0) {
			fprintf(stderr, "\n%s() failed: errno %m\n", __func__);
			break;
		}

		if (ret < size - off) {
			off += ret;
			continue;
		}

		return size;
	}

	return ret;
}

static int target_cmd_get_tid(int pid, pid_t *tid)
{
	int ret;
	int cd;

	*tid = 0;

	cd = xconnect(pid);
	if (cd < 0)
		return -1;

	ret = write(cd, &(char){CMD_GET_TID}, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	ret = xread(cd, tid, sizeof(pid_t));
	if (ret != sizeof(pid_t)) {
		fprintf(stderr, "%s() read tid failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	close(cd);
	return 0;
}

static void set_skip_addr(struct vm_skip_addr addr)
{
	int idx;

	for (idx = 0; idx < MAX_SKIP_ADDR; idx++) {
		if (skip_addr[idx].addr != NULL)
			continue;

		skip_addr[idx] = addr;

#if 0
		fprintf(stdout, "[%d] skip addr %p, desc '%c'\n", idx, skip_addr[idx].addr, skip_addr[idx].desc);
#endif
		break;
	}

	if (idx == MAX_SKIP_ADDR) {
		fprintf(stderr, "error: idx == MAX_SKIP_ADDR\n");
	}
}

static int target_cmd_get_skip_addr(int pid)
{
	int ret;
	int cd;

	cd = xconnect(pid);
	if (cd < 0)
		return cd;

	ret = write(cd, &(char){CMD_GET_SKIP_ADDR}, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	while (1) {
		struct vm_skip_addr addr;

		ret = xread(cd, &addr, sizeof(addr));
		if (ret == 0)
			break;

		set_skip_addr(addr);
	}

	close(cd);
	return 0;
}

static FILE *fopen_proc(pid_t pid, char *file_name)
{
	FILE *f;
	char path[128];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, file_name);
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "fopen() %s failed: %m\n", path);
	}

	return f;
}

struct vm_stats {
	unsigned long VmRSS;
	unsigned long RssAnon;
	unsigned long RssFile;
	unsigned long RssShmem;
};

static void get_target_rss(pid_t tid, struct vm_stats *vms)
{
	FILE *f;
	char buf[1024];

	f = fopen_proc(tid, "status");
	if (!f)
		return;

	vms->RssAnon = -1;

	while (fgets(buf, sizeof(buf), f)) {
		if (strstr(buf, "VmRSS:")) {
			sscanf(buf, "VmRSS: %lu kB", &vms->VmRSS);
		} else if (strstr(buf, "RssAnon:")) {
			sscanf(buf, "RssAnon: %lu kB", &vms->RssAnon);
		} else if (strstr(buf, "RssFile:")) {
			sscanf(buf, "RssFile: %lu kB", &vms->RssFile);
		} else if (strstr(buf, "RssShmem:")) {
			sscanf(buf, "RssShmem: %lu kB", &vms->RssShmem);
		}
	}

	fclose(f);
}

static void show_target_rss(struct vm_stats *a, struct vm_stats *b)
{
	printf("[i] vm stats\n");
	printf("[i]   VmRSS    %lu kB -> %lu kB (diff %lu kB)\n", a->VmRSS, b->VmRSS, a->VmRSS - b->VmRSS);

	if (a->RssAnon == -1) /* likely no support in kernel */
		return;

	printf("[i]   RssAnon  %lu kB -> %lu kB (diff %lu kB)\n", a->RssAnon, b->RssAnon, a->RssAnon - b->RssAnon);
#if 0
	printf("[i]   RssFile  %lu kB -> %lu kB (diff %lu kB)\n", a->RssFile, b->RssFile, a->RssFile - b->RssFile);
	printf("[i]   RssShmem %lu kB -> %lu kB (diff %lu kB)\n", a->RssShmem, b->RssShmem, a->RssShmem - b->RssShmem);
#else
	printf("[i]   RssFile  %lu kB\n", a->RssFile);
	printf("[i]   RssShmem %lu kB\n", a->RssShmem);
#endif
}

static int should_skip_range(void *start, void *end)
{
	int idx;

	for (idx = 0; idx < MAX_SKIP_ADDR; idx++) {
		if (skip_addr[idx].addr == NULL)
			break;

		if (skip_addr[idx].addr >= start && skip_addr[idx].addr < end) {
#if 0
			fprintf(stdout, "skip addr range %p..%p because of %p desc '%c'\n", start, end, skip_addr[idx].addr, skip_addr[idx].desc);
#endif
			return 1;
		}
	}

	return 0;
}

static unsigned long get_vmas_size(struct vm_area vmas[], int nr_vmas)
{
	unsigned long size = 0;
	int idx;

	for (idx = 0; idx < nr_vmas; idx++)
		size += vmas[idx].end - vmas[idx].start;

	return size;
}

static int scan_target_vmas(pid_t pid, struct vm_area vmas[], int *nr_vmas)
{
	int ret = -1;
	FILE *smaps;
	char buf[1024];

	smaps = fopen_proc(pid, "maps");
	if (!smaps)
		return ret;

	while (fgets(buf, sizeof(buf), smaps)) {
		struct vm_area *vma;
		unsigned long start, end, pgoff;
		char r,w,x,s;
		int dev_maj, dev_min;
		unsigned long ino;
		char file_path[128] = { 0 };
		char flags = FLAG_NONE;

		ret = sscanf(buf, "%lx-%lx %c%c%c%c %lx %x:%x %lu %123s", &start, &end, &r, &w, &x, &s, &pgoff, &dev_maj, &dev_min, &ino, file_path);
		if (ret < 10) {
			fprintf(stderr, "can't parse: %s", buf);
			goto err;
		}

		/* parasite stack, bss, etc. */
		if (should_skip_range((void *)start, (void *)(end + PAGE_SIZE)))
			continue;

		if (file_path[0] == '/') {
			flags = FLAG_FILE;
		} else if (file_path[0] == '\0') {
			flags = FLAG_ANON;
		} else if (!strncmp(file_path, "[stack", strlen("[stack"))) {
			flags = FLAG_STACK;
		} else if (!strncmp(file_path, "[heap", strlen("[heap"))) {
			flags = FLAG_HEAP;
		} else {
			/*
			 * sigpage, vvar, vdso, vsyscall, etc.
			 */
			continue;
		}

		if (s == 's') {
			fprintf(stdout, "[i] shared VMA %0*lx..%0*lx %s\n", 2 * (int)sizeof(unsigned long), start, 2 * (int)sizeof(unsigned long), end, file_path);
			continue;
		}

		/* skip vma that is not private */
		if (s != 'p') {
			fprintf(stderr, "unhandled VMA: %s", buf);
			assert(s == 'p');
		}

		if (*nr_vmas == MAX_VMAS) {
			fprintf(stderr, "reached MAX_VMAS!\n");
			continue;
		}

		vma = &vmas[(*nr_vmas)++];

		vma->start	= start;
		vma->end	= end;
		vma->prot	= PROT_NONE;

		if (r == 'r')
			vma->prot |= PROT_READ;
		if (w == 'w')
			vma->prot |= PROT_WRITE;
		if (x == 'x')
			vma->prot |= PROT_EXEC;

		vma->flags = flags;
	}

	ret = 0;
err:
	fclose(smaps);
	return ret;
}

static void print_target_vmas(struct vm_area vmas[], int nr_vmas, unsigned long RSS)
{
#if 0
	int idx;
#endif

	fprintf(stdout, "[i] %d candidate VMAs, VSS %ld kB, RSS %lu kB\n", nr_vmas, get_vmas_size(vmas, nr_vmas) / 1024, RSS);

#if 0
	for (idx = 0; idx < nr_vmas; idx++) {
		struct vm_area *vma = &vmas[idx];

		fprintf(stdout, "%d\t%lx-%lx %c%c%c\t%ld bytes\t(%ld kB)\n", idx, vma->start, vma->end, vma->prot & PROT_READ ? 'r' : '-', vma->prot & PROT_WRITE ? 'w' : '-', vma->prot & PROT_EXEC ? 'x' : '-', vma->end - vma->start, (vma->end - vma->start) / 1024);
	}
#endif
}

static int open_proc(pid_t pid, char *file_name)
{
	int fd;
	char path[128];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, file_name);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "fopen() %s failed: %m\n", path);
	}

	return fd;
}

static int target_cmd_mprotect(int pid, void *addr, unsigned long len, unsigned long prot)
{
	int ret;
	int cd;
	struct vm_mprotect mp = {
		.addr = addr,
		.len = len,
		.prot = prot,
	};

	cd = xconnect(pid);
	if (cd < 0)
		return cd;

	ret = write(cd, &(char){CMD_MPROTECT}, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write() cmd failed: ret %d, errno %m\n", __func__, ret);
		ret = -1;
		goto end;
	}

	ret = xwrite(cd, &mp, sizeof(mp));
	if (ret != sizeof(mp)) {
		fprintf(stderr, "%s() xwrite() mp failed: ret %d\n", __func__, ret);
		ret = -1;
	}

end:
	close(cd);
	return ret;
}

static int get_single_page(int cd, void *addr, int fd)
{
	int ret;
	struct vm_page_addr req = {
		.addr = addr,
	};
	struct vm_page page;

	ret = xwrite(cd, &req, sizeof(req));
	if (ret != sizeof(req)) {
		fprintf(stderr, "%s() xwrite(req) failed: %d\n", __func__, ret);
		return -1;
	}

	ret = xread(cd, &page, sizeof(page));
	if (ret < 0) {
		fprintf(stderr, "%s() xread(page) failed: %d\n", __func__, ret);
		return -2;
	}

	ret = xwrite(fd, &page, ret);
	if (ret < 0) {
		fprintf(stderr, "%s() xwrite(page) failed: %d\n", __func__, ret);
		return -3;
	}

	return 0;
}

#define PME_PRESENT_IN_RAM		(1ULL << 63)
#define PME_PRESENT_IN_SWAP		(1ULL << 62)

static int get_vma_pages(int cd, pid_t pid, struct vm_area *vma, int pd)
{
	int ret;
	int md;
	uint64_t off;
	unsigned long nrpages;
	unsigned long pfn;
	unsigned long nrpages_dumpable = 0;

	md = open_proc(pid, "pagemap");
	if (md < 0)
		return -EIO;

	nrpages = ((vma->end - vma->start) / PAGE_SIZE);

	pfn = vma->start / PAGE_SIZE;
	off = pfn * sizeof(uint64_t);
	off = lseek(md, off, SEEK_SET);
	if (off != pfn * sizeof(uint64_t)) {
		fprintf(stderr, "lseek() off %lu: %m\n", (unsigned long)off);
		close(md);
		return -1;
	}

	for (pfn = 0; pfn < nrpages; pfn++) {
		uint64_t map;
		unsigned long vaddr;

		vaddr = vma->start + pfn * PAGE_SIZE;

		ret = read(md, &map, sizeof(map));
		if (ret != sizeof(map)) {
			fprintf(stderr, "read() %m\n");
			continue;
		}

		if (map & (PME_PRESENT_IN_RAM | PME_PRESENT_IN_SWAP)) {
			nrpages_dumpable++;
			get_single_page(cd, (void *)vaddr, pd);
		}
	}

	close(md);

	if (nrpages_dumpable) {
		char *desc;

		if (vma->flags == FLAG_NONE) {
			desc = "none";
		} else if (vma->flags == FLAG_STACK) {
			desc = "stck";
		} else if (vma->flags == FLAG_HEAP) {
			desc = "heap";
		} else if (vma->flags == FLAG_ANON) {
			desc = "anon";
		} else if (vma->flags == FLAG_FILE) {
			desc = "file";
		}

		fprintf(stdout, "[i]   %0*lx..%0*lx  %s %6ld kB\n", 2 * (int)sizeof(unsigned long), vma->start, 2 * (int)sizeof(unsigned long), vma->end, desc, (nrpages_dumpable * PAGE_SIZE) / 1024);
	}

	return 0;
}

static int get_target_pages(int pid, struct vm_area vmas[], int nr_vmas)
{
	int ret;
	char name[128];
	int fd;
	int cd;
	int idx;

	snprintf(name, sizeof(name), "%s/pages-%d.img", dump_dir, pid);

	fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "%s() open failed with: %m\n", __func__);
		return -1;
	}

	cd = xconnect(pid);
	if (cd < 0) {
		close(fd);
		return cd;
	}

	ret = write(cd, &(char){CMD_GET_PAGES}, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
		ret = -1;
		goto out;
	}

	for (idx = 0; idx < nr_vmas; idx++) {
		if (vmas[idx].flags & FLAG_ANON || vmas[idx].flags & FLAG_HEAP || vmas[idx].flags & FLAG_STACK) {
			get_vma_pages(cd, pid, &vmas[idx], fd);
		}
	}

out:
	close(cd);
	close(fd);
	return 0;
}

static void target_vmas_mprotect_off(int pid)
{
	int idx;
	struct vm_area *vma;

	for (idx = 0; idx < nr_vmas; idx++) {
		vma = &vmas[idx];

		if ((vma->prot & PROT_READ) && (vma->prot & PROT_WRITE))
			continue;

		target_cmd_mprotect(pid, (void *)vma->start, vma->end - vma->start, vma->prot | PROT_READ | PROT_WRITE);
	}
}

static void target_vmas_mprotect_on(int pid)
{
	int idx;
	struct vm_area *vma;

	for (idx = 0; idx < nr_vmas; idx++) {
		vma = &vmas[idx];

		if ((vma->prot & PROT_READ) && (vma->prot & PROT_WRITE))
			continue;

		target_cmd_mprotect(pid, (void *)vma->start, vma->end - vma->start, vma->prot);
	}
}

static int target_set_pages(pid_t pid)
{
	int ret;
	int cd;
	char cmd = CMD_SET_PAGES;
	char name[128];
	int fd;

	snprintf(name, sizeof(name), "%s/pages-%d.img", dump_dir, pid);

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s() open failed with: %m\n", __func__);
		return -1;
	}

	cd = xconnect(pid);
	if (cd < 0) {
		close(fd);
		return cd;
	}

	ret = write(cd, &cmd, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	while (1) {
		struct vm_page page;

		ret = xread(fd, &page, sizeof(page));
		if (ret == 0)
			break;

		ret = xwrite(cd, &page, ret);
		if (ret < 0) {
			fprintf(stderr, "%s() xwrite failed with: %m\n", __func__);
			break;
		}
	}

	close(cd);
	close(fd);
	unlink(name);
	return ret;
}

static int target_cmd_end(int pid)
{
	int ret;
	int cd;
	char cmd = CMD_END;

	cd = xconnect(pid);
	if (cd < 0)
		return cd;

	ret = write(cd, &cmd, 1);
	if (ret != 1) {
		fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	xread(cd, &cmd, sizeof(cmd));
	if (cmd != CMD_END)
		fprintf(stdout, "%s() unexpected response: %d\n", __func__, cmd);

	close(cd);
	return ret;
}

static void cleanup_socket(int pid)
{
	char socketaddr[108];
	create_filesystem_socketname(socketaddr, sizeof(socketaddr), pid);
	remove(socketaddr);
}

static long diff_ms(struct timespec *ts)
{
	struct timespec tsn;

	clock_gettime(CLOCK_MONOTONIC, &tsn);

	return (tsn.tv_sec*1000 + tsn.tv_nsec/1000000) - (ts->tv_sec*1000 + ts->tv_nsec/1000000);
}

static int send_response_to_client(int fd, memcr_svc_response resp_code)
{
	struct service_response svc_resp = { .resp_code = resp_code };
	int ret = xwrite(fd, &svc_resp, sizeof(svc_resp)); // send resp to client
	if (ret != sizeof(svc_resp))
	{
		fprintf(stderr, "Error sending checkpoint response. Client may not exist!\n");
		return -1;
	}

	return 0;
}

static int send_response_to_service(int fd, int status)
{
	struct service_response svc_resp = { .resp_code = MEMCR_OK };

	if (status)
		svc_resp.resp_code = MEMCR_ERROR;

	fprintf(stdout, "[%d] Sending %s response.\n", getpid(), (status ? "ERROR" : "OK"));
	int ret = xwrite(fd, &svc_resp, sizeof(svc_resp)); // send resp to service
	if (ret != sizeof(svc_resp))
		return -1;

	return 0;
}

static int cmd_checkpoint(pid_t pid)
{
	int ret;
	pid_t tpid;
	struct vm_stats vms_a, vms_b;
	struct timespec ts;

	ret = target_cmd_get_tid(pid, &tpid);
	if (ret == -1) {
		fprintf(stderr, "CMD_GET_TID failed\n");
		return ret;
	}

	if (tpid != parasite_pid) {
		fprintf(stdout, "[i] parasite pid %d (LXC pid %d)\n", parasite_pid, tpid);
	} else {
		fprintf(stdout, "[i] parasite pid %d (no LXC)\n", parasite_pid);
	}

	ret = target_cmd_get_skip_addr(pid);
	if (ret) {
		fprintf(stderr, "GET ADDR failed: ret %d\n", ret);
		return 1;
	}

	ret = scan_target_vmas(pid, vmas, &nr_vmas);
	if (ret) {
		fprintf(stderr, "scan_target_vmas() failed: ret %d\n", ret);
		return 1;
	}

	get_target_rss(pid, &vms_a);

	print_target_vmas(vmas, nr_vmas, vms_a.VmRSS);

	fprintf(stdout, "[+] mprotect off\n");
	target_vmas_mprotect_off(pid);

	fprintf(stdout, "[+] downloading pages\n");
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ret = get_target_pages(pid, vmas, nr_vmas);
	if (ret) {
		fprintf(stderr, "get_target_pages() failed\n");
		exit(1);
	}
	fprintf(stdout, "[i] download took %lu ms\n", diff_ms(&ts));
	fprintf(stdout, "[i] stored at %s/pages-%d.img\n", dump_dir, pid);

	get_target_rss(pid, &vms_b);

	show_target_rss(&vms_a, &vms_b);

	return 0;
}

static int cmd_restore(pid_t pid)
{
	struct timespec ts;

	fprintf(stdout, "[+] uploading pages\n");
	clock_gettime(CLOCK_MONOTONIC, &ts);
	target_set_pages(pid);
	fprintf(stdout, "[i] upload took %lu ms\n", diff_ms(&ts));

	fprintf(stdout, "[+] mprotect on\n");
	target_vmas_mprotect_on(pid);

	/*
	 * This is needed to avoid a race between freezer and target when target sets up its memory
	 * and freezer can unseize too early. To achieve that we send one more command that will be
	 * handled once previous one (set pages) is done.
	 */
	target_cmd_end(pid);

	if (socket_dir) {
		cleanup_socket(pid);
	}

	return 0;
}

static int read_cpu_regs(pid_t pid, struct registers *regs)
{
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};

	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static int write_cpu_regs(pid_t pid, struct registers *regs)
{
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof(*regs)
	};

	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static unsigned long execute_blob(pid_t tid, unsigned long *pc, const char *blob, size_t size, unsigned long *arg0, unsigned long *arg1)
{
	int ret;
	struct registers regs, saved_regs;

	siginfo_t si;
	int i, status;

	/* inject blob into the host */
	for (i = 0; i < DIV_ROUND_UP(size, sizeof(unsigned long)); i++) {
		ret = ptrace(PTRACE_POKEDATA, tid, pc + i, (void *)*((unsigned long *)blob + i));
		if (ret) {
			fprintf(stderr, "ptrace(PTRACE_POKEDATA) failed: %m\n");
			assert(!ret);
		}
	}

retry:
	read_cpu_regs(tid, &regs);
	saved_regs = regs;
	set_cpu_regs(&regs, pc, arg0 ? *arg0 : 0, arg1 ? *arg1 : 0);
	write_cpu_regs(tid, &regs);

	/* let the blob run, upon completion it will trigger debug trap */
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));

#if defined (__x86_64__)
	if (WSTOPSIG(status) != SIGTRAP || si.si_code != SI_KERNEL) { /* TODO */
#elif defined (__arm__) || defined(__aarch64__)
	if (WSTOPSIG(status) != SIGTRAP || si.si_code != 1) {
#endif
		/*
		 * The only other thing which can happen is signal
		 * delivery.  Restore registers so that signal frame
		 * preparation operates on the original state, schedule
		 * INTERRUPT and let the delivery happen.
		 *
		 * If the signal has user handler, signal code will
		 * schedule handler by modifying userland memory and
		 * registers and return to jobctl trap.  STOP handling will
		 * modify jobctl state and also return to jobctl trap and
		 * there isn't much we can do about KILL handling.
		 *
		 * So, regardless of signo, we can simply retry after
		 * control returns to jboctl trap.
		 *
		 * Note that if signal is delivered between syscall and
		 * int3 in the blob, the syscall might be executed again.
		 * Block signals first before doing any operation with side
		 * effects.
		 */
	retry_signal:
		printf("** delivering signal %d si_code=%d\n", si.si_signo, si.si_code);
#if defined(__x86_64__)
		assert(si.si_code <= 0); /* TODO arm */
#endif
		write_cpu_regs(tid, &saved_regs);

		assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
		assert(!ptrace(PTRACE_CONT, tid, NULL,
				   (void *)(unsigned long)si.si_signo));

		/* wait for trap */
		assert(wait4(tid, &status, __WALL, NULL) == tid);
		assert(WIFSTOPPED(status));
		assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));

		/* are we back at jobctl trap or are there more signals? */
		if (si.si_code >> 8 != PTRACE_EVENT_STOP)
			goto retry_signal;

		/* otherwise, retry */
		goto retry;
	}

	/*
	 * Okay, this is the SIGTRAP delivery from int 3 / udf 16 / brk 0. Steer the thread
	 * back to jobctl trap by raising INTERRUPT and squashing SIGTRAP.
	 */
	assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));

	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));
	assert(SI_EVENT(si.si_code) == PTRACE_EVENT_STOP);

	/* retrieve return value and restore registers */
	read_cpu_regs(tid, &regs);
	write_cpu_regs(tid, &saved_regs);

	if (arg0)
		*arg0 = get_cpu_syscall_arg0(&regs);

	return get_cpu_syscall_ret(&regs);
}

static int update_parasite_pid(pid_t pid)
{
	int idx;

	for (idx = 0; idx < nr_threads; idx++)
		if (pid == tids[idx])
			return 0;

	parasite_pid = pid;
	return 0;
}

static int setup_parasite_args(pid_t pid, void *base)
{
	struct parasite_args pa;
	unsigned long *pa_src = (unsigned long *)&pa;
	unsigned long *pa_dst;
	int i;

	pa_dst = (unsigned long *)PARASITE_ARGS_ADDR(base);

	if (socket_dir) {
		create_filesystem_socketname(pa.addr, sizeof(pa.addr), pid);
	} else {
		create_abstract_socketname(pa.addr, sizeof(pa.addr), pid);
	}

	for (i = 0; i < DIV_ROUND_UP(sizeof(struct parasite_args), sizeof(unsigned long)); i++) {
		assert(!ptrace(PTRACE_POKEDATA, pid, pa_dst + i, *(pa_src + i)));
	}

	return 0;
}

static int execute_parasite_checkpoint(pid_t pid)
{
	struct registers regs;
	unsigned long arg0, ret;
	pid_t parasite;
	int i, status;
	struct vm_skip_addr paddr;

	read_cpu_regs(pid, &regs);

#if 0
	print_cpu_regs(&regs);
#endif

	/* allocate space to save original code */
	ctx.count = DIV_ROUND_UP(MAX(test_blob_size,
				 MAX(sigprocmask_blob_size,
				 MAX(mmap_blob_size,
				 MAX(clone_blob_size,
				 munmap_blob_size)))),
				 sizeof(unsigned long));

	ctx.saved_code = malloc(sizeof(unsigned long) * ctx.count);
	assert(ctx.saved_code);

	/*
	 * The page %rip is on gotta be executable.  If we inject from the
	 * beginning of the page, there should be at least one page of
	 * space.  Determine the position and save the original code.
	 */
	ctx.pc = (void *)round_down((unsigned long)get_cpu_regs_pc(&regs), PAGE_SIZE);
	for (i = 0; i < ctx.count; i++) {
		ctx.saved_code[i] = ptrace(PTRACE_PEEKDATA, pid, ctx.pc + i, NULL);
#if 0
		fprintf(stdout, "code[%d]\t%s %0*lx\n", i, i > 9 ? "" : "\t", 2 * (int)sizeof(unsigned long), ctx.saved_code[i]);
#endif
	}

	/*
	 * Save and restore some bytes below %rsp so that blobs can use it
	 * as writeable scratch area.  This wouldn't be necessary if mmap
	 * is done earlier.
	 */
	ctx.sp = get_cpu_regs_sp(&regs) - sizeof(ctx.saved_stack);
	for (i = 0; i < sizeof(ctx.saved_stack) / sizeof(ctx.saved_stack[0]); i++) {
		ctx.saved_stack[i] = ptrace(PTRACE_PEEKDATA, pid, ctx.sp + i, NULL);
#if 0
		fprintf(stdout, "stack[%d]\t %0*lx\n", i, 2 * (int)sizeof(unsigned long), ctx.saved_stack[i]);
#endif
	}

#if 0
	/* say hi! */
	printf("executing test blob\n");
	execute_blob(pid, pc, test_blob, test_blob_size, NULL, NULL);
#endif

	/*
	 * block all signals
	 *
	 * TODO: this code works correctly on x86_64 as kernel sigmask_t size is 8 bytes.
	 * On ARM extra handling is needed to load and store these 8 bytes.
	 * Upper half is occupied by RT signals so shouldn't matter during PoC
	 * if we restore them correctly.
	 */
	printf("[+] blocking all signals\n");
	for (i = 0; i < 8 / sizeof(unsigned long); i++) {
		assert(!ptrace(PTRACE_POKEDATA, pid, ctx.sp-i, (void *)-1LU));
	}
	arg0 = (unsigned long)ctx.sp;
	ret = execute_blob(pid, ctx.pc, sigprocmask_blob, sigprocmask_blob_size, &arg0, NULL);
#if 0
	printf(" = %#lx, prev_sigmask %#lx\n", ret, arg0);
#endif
	ctx.saved_sigmask = arg0;
	assert(!ret);

	/* mmap space for parasite */
#if 0
	printf("executing mmap blob\n");
#endif
	arg0 = sizeof(parasite_blob);
	ret = execute_blob(pid, ctx.pc, mmap_blob, mmap_blob_size, &arg0, NULL);
#if 0
	printf(" = %#lx\n", ret);
#endif
	assert(ret < -4096LU);

	/* copy parasite_blob into the mmapped area */
	ctx.dst = (void *)ret;
	ctx.src = (void *)parasite_blob;
	for (i = 0; i < DIV_ROUND_UP(sizeof(parasite_blob), sizeof(unsigned long)); i++)
		assert(!ptrace(PTRACE_POKEDATA, pid, ctx.dst + i, ctx.src[i]));

	setup_parasite_args(pid, ctx.dst);

	/* skip parasite vma */
	paddr.addr = ctx.dst;
	paddr.desc = 's';
	set_skip_addr(paddr);

	/* clone parasite which will trap and wait for instruction */
#if 0
	printf("executing clone blob\n");
#endif
	arg0 = (unsigned long)ctx.dst;
	parasite = execute_blob(pid, ctx.pc, clone_blob, clone_blob_size, &arg0, NULL);
#if 0
	printf(" = %d\n", parasite);
#endif
	assert(parasite >= 0);

	/* translate lxc ns pid to global one */
	iterate_pstree(pid, 0, MAX_THREADS, update_parasite_pid);

	parasite = parasite_pid;

	/* let the parasite run and wait for completion */
	ret = wait4(parasite, &status, __WALL, NULL);
	if (ret != parasite) {
		fprintf(stderr, "[-] wait4 ret %ld != parasite %d, errno %m\n", ret, parasite);
		assert(ret == parasite);
	}
	assert(WIFSTOPPED(status));
	printf("[+] executing parasite\n");
	assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));

	cmd_checkpoint(pid);

	return 0;
}

static int execute_parasite_restore(pid_t pid)
{
	unsigned long arg0, arg1, ret;
	pid_t parasite = parasite_pid;
	int i, status;

	cmd_restore(pid);

	/* wait for termination */
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	if (WIFEXITED(status)) {
#if 0
		fprintf(stdout, "WIFEXITED(status) = 0x%x\n", WIFEXITED(status));
#endif
		assert(WIFEXITED(status));
	}

	/* parasite is done, munmap parasite_blob area */
#if 0
	printf("executing munmap blob\n");
#endif
	arg0 = (unsigned long)ctx.dst;
	arg1 = sizeof(parasite_blob);
	ret = execute_blob(pid, ctx.pc, munmap_blob, munmap_blob_size, &arg0, &arg1);
	if (ret) {
		fprintf(stderr, "[-] munmap_blob failed: %ld\n", ret);
		assert(!ret);
	}

	/* restore the original sigmask */
	printf("[+] unblocking signals\n");
	assert(!ptrace(PTRACE_POKEDATA, pid, ctx.sp, (void *)ctx.saved_sigmask));
	arg0 = (unsigned long)ctx.sp;
	ret = execute_blob(pid, ctx.pc, sigprocmask_blob, sigprocmask_blob_size, &arg0, NULL);
#if 0
	printf(" = %#lx, prev_sigmask %#lx\n", ret, arg0);
#endif
	assert(!ret);

	/* restore the original code and stack area */
	for (i = 0; i < ctx.count; i++)
		assert(!ptrace(PTRACE_POKEDATA, pid, ctx.pc + i, (void *)ctx.saved_code[i]));

	for (i = 0; i < sizeof(ctx.saved_stack) / sizeof(ctx.saved_stack[0]); i++)
		assert(!ptrace(PTRACE_POKEDATA, pid, ctx.sp + i, (void *)ctx.saved_stack[i]));

	free(ctx.saved_code);

	return 0;
}

static void signal_handler(int signal)
{
	if (signal == SIGINT) {
		interrupted = 1;
		fprintf(stdout, "%s() got SIGINT\n", __func__);
	} else {
		fprintf(stderr, "%s() unexpected signal %d\n", __func__, signal);
	}
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s [-p pid] [-n]\n" \
		"options: \n" \
		"  -h --help\thelp\n" \
		"  -d --dir\tdir where memory dump is stored (defaults to /tmp)\n" \
		"  -S --parasite-socket-dir\tdir where socket to communicate with parasite is created\n" \
		"        (abstract socket will be used if no path specified)\n" \
		"  -n --nowait\tno wait for key press\n",
		name);
	exit(status);
}

static struct sockaddr_un make_restore_socket_address(pid_t pid)
{
	struct sockaddr_un addr_restore;
	addr_restore.sun_family = PF_UNIX;
	memset(addr_restore.sun_path, 0, sizeof(addr_restore.sun_path));
	snprintf(addr_restore.sun_path, sizeof(addr_restore.sun_path), "#memcrRestore%u", pid);
	addr_restore.sun_path[0] = '\0';

	return addr_restore;
}

static int setup_restore_socket_worker(pid_t pid)
{
	int ret, rsd;
	struct sockaddr_un addr_restore = make_restore_socket_address(pid);

	rsd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (rsd < 0) {
		fprintf(stderr, "%s() failed on socket setup.\n", __func__);
		return rsd;
	}

	ret = bind(rsd, (struct sockaddr *)&addr_restore, sizeof(addr_restore));
	if (ret < 0) {
		fprintf(stderr, "%s() failed on socket bind.\n", __func__);
		return ret;
	}
	ret = listen(rsd, 8);
	if (ret < 0) {
		fprintf(stderr, "%s() failed on socket listen.\n", __func__);
		return ret;
	}

	return rsd;
}

static int setup_restore_socket_service(pid_t pid)
{
	int rd, ret;
	struct sockaddr_un addr_restore = make_restore_socket_address(pid);

	rd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (rd < 0) {
		fprintf(stderr, "socket() %s failed: %m\n", addr_restore.sun_path + 1);
		return rd;
	}

	ret = connect(rd, (struct sockaddr *)&addr_restore, sizeof(struct sockaddr_un));
	if (ret < 0) {
		fprintf(stderr, "connect() to %s failed: %m\n", addr_restore.sun_path + 1);
		close(rd);
		return ret;
	}
	return rd;
}

static int checkpoint_worker(pid_t pid, int checkpointSocket)
{
	int ret = seize_target(pid);
	if (ret)
	{
		fprintf(stderr, "[%d] Seizing target failed!\n", getpid());
		return ret;
	}

	ret = execute_parasite_checkpoint(pid);
	if(ret)
	{
		fprintf(stderr, "[%d] Parasite checkpoint failed!\n", getpid());
		return ret;
	}

	return 0;
}

static int restore_worker(int rd)
{
	int ret;
	struct service_command post_checkpoint_cmd;

	ret = xread(rd, &post_checkpoint_cmd, sizeof(post_checkpoint_cmd));
	if (ret != sizeof(post_checkpoint_cmd))
		return -1;

	if (MEMCR_RESTORE != post_checkpoint_cmd.cmd)
	{
		fprintf(stdout, "[%d] Unknown command %d received.\n", getpid(), post_checkpoint_cmd.cmd);
		return -1;
	}

	fprintf(stdout, "[%d] Worker received RESTORE command for %d.\n", getpid(), post_checkpoint_cmd.pid);

	ret = execute_parasite_restore(post_checkpoint_cmd.pid);
	if (ret)
		return ret;

	ret = unseize_target();
	return ret;
}

static int application_worker(pid_t pid, int checkpoint_resp_socket)
{
	int rsd, rd, ret = 0;

	fprintf(stdout, "[%d] memcr worker is started to checkpoint %d.\n", getpid(), pid);

	rsd = setup_restore_socket_worker(pid);
	if (rsd < 0)
		ret |= rsd;

	if (0 == ret)
	{
		ret |= checkpoint_worker(pid, checkpoint_resp_socket);
	}
	ret |= send_response_to_service(checkpoint_resp_socket, ret); // send resp to service
	close(checkpoint_resp_socket);

	if (ret)
	{
		fprintf(stderr, "[%d] Process %d checkpoint failed! Aborting procedure.\n", getpid(), pid);
		close(rsd);
		return ret;
	}

	fprintf(stdout, "[%d] Waiting for restore command...\n", getpid());
	rd = accept(rsd, NULL, NULL);
	if (rd < 0) {
		fprintf(stderr, "%s() failed on socket accept.\n", __func__);
		close(rsd);
		ret |= rd;
	}

	if (0 == ret)
	{
		ret |= restore_worker(rd);
	}
	ret |= send_response_to_service(rd, ret);

	close(rsd);
	close(rd);
	fprintf(stdout, "[%d] Worker ends.\n", getpid());

	return ret;
}

static void parent_checkpoint_procedure(int checkpointSocket, int cd)
{
	int ret;
	struct service_response svc_resp;

	fprintf(stdout, "[+] Parent waiting for worker checkpoint...\n");
	ret = xread(checkpointSocket, &svc_resp, sizeof(svc_resp)); // receive resp from child
	close(checkpointSocket);

	if (ret == sizeof(svc_resp))
	{
		fprintf(stdout, "[+] Parent received checkpoint response, informing client...\n");
		send_response_to_client(cd, svc_resp.resp_code);
	}
	else
	{
		fprintf(stderr, "[!] Error reading checkpoint response from worker!\n");
		send_response_to_client(cd, MEMCR_ERROR);
	}
}

static void parent_restore_procedure(int cd, struct service_command svc_cmd)
{
	int rd, ret = 0;
	struct service_response svc_resp;

	rd = setup_restore_socket_service(svc_cmd.pid);
	if (rd < 0)
	{
		fprintf(stderr, "[!] Error in setup restore connection to worker!\n");
		ret = -1;
	}

	ret = xwrite(rd, &svc_cmd, sizeof(svc_cmd)); // send restore to child
	if (ret != sizeof(svc_cmd)) {
		fprintf(stderr, "%s() xwrite() svc_cmd failed: ret %d\n", __func__, ret);
		ret = -1;
	}

	fprintf(stdout, "[+] Parent waiting for worker to restore... \n");

	ret = xread(rd, &svc_resp, sizeof(svc_resp));   // read response from child
	close(rd);
	if (ret != sizeof(svc_resp)) {
		fprintf(stderr, "%s() xread() svc_resp failed: ret %d\n", __func__, ret);
		ret = -1;
	}

	if (-1 == ret || MEMCR_OK != svc_resp.resp_code)
	{
		fprintf(stderr, "[!] There were errors during restore procedure, sending ERROR response to client!\n");
		send_response_to_client(cd, MEMCR_ERROR);
	}
	else
	{
		fprintf(stdout, "[i] Restore procedure finished. Sending OK response to client.\n");
		send_response_to_client(cd, MEMCR_OK);
	}
}

static int handle_connection(int cd)
{
	int ret;
	struct service_command svc_cmd;

	ret = xread(cd, &svc_cmd, sizeof(svc_cmd));
	if (ret != sizeof(svc_cmd)) {
		fprintf(stderr, "%s() read command: ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	switch (svc_cmd.cmd) {
		case MEMCR_CHECKPOINT: {
			fprintf(stdout, "[+] got MEMCR_CHECKPOINT for %d.\n", svc_cmd.pid);

			int checkpoint_resp_sockets[2];

			ret = socketpair(AF_UNIX, SOCK_STREAM, 0, checkpoint_resp_sockets);
			if (ret < 0)
			{
				fprintf(stderr, "Error in socketpair creation!\n");
				return ret;
			}

			pid_t forkpid = fork();
			if (0 == forkpid) // child
			{
				close(cd);
				close(checkpoint_resp_sockets[0]);

				ret = application_worker(svc_cmd.pid, checkpoint_resp_sockets[1]);
				exit(ret);
			}
			else if (forkpid > 0) // parent
			{
				close(checkpoint_resp_sockets[1]);

				parent_checkpoint_procedure(checkpoint_resp_sockets[0], cd);
			}
			else
			{
				fprintf(stderr, "What the fork!\n");
			}

			break;
		}
		case MEMCR_RESTORE: {
			fprintf(stdout, "[+] got MEMCR_RESTORE for %d.\n", svc_cmd.pid);

			parent_restore_procedure(cd, svc_cmd);

			break;
		}
		case MEMCR_EXIT: {
			fprintf(stdout, "[+] Good bye!\n");
			send_response_to_client(cd, MEMCR_OK);
			finish = 1;
			break;
		}
		default:
			fprintf(stderr, "%s() unexpected command %d\n", __func__, svc_cmd.cmd);
			break;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	int opt;
	int option_index;
	int srvd;
	struct sockaddr_un addr;

	static struct option long_options[] = {
		{ "help",			0,	0,	0},
		{ "dir",			1,	0,	0},
		{ "parasite-socket-dir",	1,	0,	0},
		{ "nowait",			0,	0,	0},
		{ NULL,			0,	0,	0}
	};

	dump_dir = "/tmp";
	socket_dir = NULL;

	while ((opt = getopt_long(argc, argv, "hvp:d:S:n", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'd':
				dump_dir = optarg;
				break;
			case 'S':
				socket_dir = optarg;
				break;
			case 'n':
				nowait = 1;
				break;
			default: /* '?' */
				usage(argv[0], 1);
		}
	}

	signal(SIGINT, signal_handler);

	fprintf(stdout, "Starting memcr service. Dumps will be stored in: %s\n", dump_dir);

	srvd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (srvd < 0) {
		return -1;
	}

	addr.sun_family = PF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/memcrservice");

	remove("/tmp/memcrservice");
	ret = bind(srvd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		return ret;
	}
	ret = listen(srvd, 8);
	if (ret < 0) {
		return ret;
	}

	int flags = fcntl(srvd, F_GETFL, 0);
	fcntl(srvd, F_SETFL, flags | O_NONBLOCK);

	fprintf(stdout, "[+] Listening on a socket for requests...\n");
	while (!finish) {
		ret = accept(srvd, NULL, NULL);
		if (ret < 0) {
			usleep(1000);
			//fprintf(stdout, "[+] sleeping...\n");
		} else {
			fprintf(stdout, "[+] Handling request...\n");
			handle_connection(ret);
			close(ret);
			fprintf(stdout, "[+] Request handled...\n");
		}
	}

	close(srvd);

	return interrupted ? 1 : 0;
}

