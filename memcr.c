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
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <dirent.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <sys/param.h> /* MIN(), MAX() */
#include <sys/mman.h>

#ifdef COMPRESS_LZ4
#include <lz4.h>
#endif

#ifdef CHECKSUM_MD5
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#else
#include <openssl/md5.h>
#endif
#endif

#include "memcr.h"
#include "arch/cpu.h"
#include "arch/enter.h"
#include "parasite-blob.h"

#ifndef ARCH_NAME
#define ARCH_NAME "unknown"
#endif

#define NT_PRSTATUS 1

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#ifndef SI_FROMUSER
#define SI_FROMUSER(siptr)	((siptr)->si_code <= 0)
#endif

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

static char *flag_desc[5] = {
	[FLAG_NONE]	= "none",
	[FLAG_STACK]	= "stck",
	[FLAG_HEAP]	= "heap",
	[FLAG_ANON]	= "anon",
	[FLAG_FILE]	= "file",
};

#define DEBUG_SIGSET	0

struct vm_area {
	unsigned long start;
	unsigned long end;
	unsigned long prot;
	unsigned long flags;
};

static char *dump_dir;
static char *parasite_socket_dir;
static int parasite_socket_use_netns;
static int no_wait;
static int proc_mem;
static int rss_file;
static int compress;
static int checksum;
static int service;
static unsigned int timeout;

static unsigned int page_size;

#define BIT(x) (1ULL << x)

#define PM_PAGE_FRAME_NUMBER_MASK	0x007fffffffffffff
#define PM_PAGE_FILE_OR_SHARED_ANON	61
#define PM_PAGE_SWAPPED			62
#define PM_PAGE_PRESENT			63

#define KPF_UNEVICTABLE			18	/* (since Linux 2.6.31) */

static int kpageflags_fd;

#define PATH_MAX			4096
#define MAX_THREADS			1024

static pid_t tids[MAX_THREADS];
static int nr_threads;

#define SERVICE_MODE_SELECT_TIMEOUT_MS	100

#define MAX_VMAS			(3*4096)
static struct vm_area vmas[MAX_VMAS];
static int nr_vmas;

#define MAX_VM_REGION_SIZE (1 * 1024 * 1024)

#ifdef COMPRESS_LZ4
#define MAX_LZ4_DST_SIZE LZ4_compressBound(MAX_VM_REGION_SIZE)
#endif

static pid_t parasite_pid;
static pid_t parasite_pid_clone;
static struct target_context ctx;

static sig_atomic_t interrupted;

static struct {
	pthread_t thread_id;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int changed;
	int status;
} parasite_watch = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
};

/*
 * man sigaction: For a ptrace(2) event, si_code will contain SIG‐TRAP and have the ptrace event in the high byte:
 * (SIGTRAP | PTRACE_EVENT_foo << 8).
 */
#define SI_EVENT(si_code)	(((si_code) & 0xFF00) >> 8)

/*
 * These functions are used for interacting with a dump file and are declared
 * as weak symbols so that a shared library can provide them.
 */
int __attribute__((weak)) lib__open(const char *pathname, int flags, mode_t mode);
int __attribute__((weak)) lib__close(int fd);
int __attribute__((weak)) lib__read(int fd, void *buf, size_t count);
int __attribute__((weak)) lib__write(int fd, const void *buf, size_t count);
int __attribute__((weak)) lib__init(int enable, const char *arg);
int __attribute__((weak)) lib__fini(void);

#define CHECKPOINTED_PIDS_LIMIT 48
#define PID_INVALID		0
#define STATE_RESTORED			0
#define STATE_CHECKPOINTING		1
#define STATE_CHECKPOINTED		2

static pthread_mutex_t checkpoint_service_data_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
	pid_t pid;
	pid_t worker;
	int state;
	int checkpoint_abort;
	int checkpoint_cmd_sd;
} checkpoint_service_data[CHECKPOINTED_PIDS_LIMIT];

#define SOCKET_INVALID				(-1)
static int checkpoint_service_socket = SOCKET_INVALID;

#define TRUE		1
#define FALSE		0

#define MAX_CLIENT_CONNECTIONS		8

struct service_command_ctx {
	struct service_command svc_cmd;
	int cd;
};

static struct {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct service_command_ctx svc_ctxs[MAX_CLIENT_CONNECTIONS];
	int front_idx;
	int back_idx;
	size_t size;
	int interrupt;
} service_cmds_ctx = { .lock = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER };

static int service_cmds_push_back(struct service_command_ctx *ctx)
{
	int ret = 0;
	pthread_mutex_lock(&service_cmds_ctx.lock);
	if (service_cmds_ctx.size >= MAX_CLIENT_CONNECTIONS) {
		fprintf(stderr, "[-] %s: Commands queue full\n", __func__);
		ret = 1;
		goto err;
	}

	service_cmds_ctx.svc_ctxs[service_cmds_ctx.back_idx] = *ctx;
	service_cmds_ctx.back_idx++;
	service_cmds_ctx.size++;
	if(service_cmds_ctx.back_idx >= MAX_CLIENT_CONNECTIONS)
		service_cmds_ctx.back_idx = 0;

	pthread_cond_signal(&service_cmds_ctx.cond);

err:
	pthread_mutex_unlock(&service_cmds_ctx.lock);
	return ret;
}

static int service_cmds_wait_and_pop_front(struct service_command_ctx *ctx)
{
	int ret = 0;
	pthread_mutex_lock(&service_cmds_ctx.lock);
	while (service_cmds_ctx.size == 0 && service_cmds_ctx.interrupt == FALSE && ret == 0)
		ret = pthread_cond_wait(&service_cmds_ctx.cond, &service_cmds_ctx.lock);

	if (!ret && service_cmds_ctx.size > 0 && service_cmds_ctx.interrupt == FALSE) {
		*ctx = service_cmds_ctx.svc_ctxs[service_cmds_ctx.front_idx];
		service_cmds_ctx.front_idx++;
		service_cmds_ctx.size--;
		if(service_cmds_ctx.front_idx >= MAX_CLIENT_CONNECTIONS)
			service_cmds_ctx.front_idx = 0;
	} else if (service_cmds_ctx.interrupt == TRUE)
		ret = 1;
	else
		fprintf(stderr, "[-] %s: pthread_cond_wait() failed: %d\n", __func__, ret);

	pthread_mutex_unlock(&service_cmds_ctx.lock);
	return ret;
}

static void service_cmds_interrupt(void)
{
	pthread_mutex_lock(&service_cmds_ctx.lock);
	service_cmds_ctx.interrupt = TRUE;
	pthread_cond_signal(&service_cmds_ctx.cond);
	pthread_mutex_unlock(&service_cmds_ctx.lock);
}

#ifdef CHECKSUM_MD5
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define MD5_DIGEST_SIZE		EVP_MAX_MD_SIZE
static EVP_MD_CTX *md5_checkpoint_ctx;
static EVP_MD_CTX *md5_restore_ctx;
#else
#define MD5_DIGEST_SIZE		MD5_DIGEST_LENGTH
static MD5_CTX md5_checkpoint_ctx;
static MD5_CTX md5_restore_ctx;
#endif

static unsigned char md5_checkpoint_digest[MD5_DIGEST_SIZE];
static unsigned int md5_checkpoint_digest_len;
static unsigned char md5_restore_digest[MD5_DIGEST_SIZE];
static unsigned int md5_restore_digest_len;

static void md5_init(void *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	const EVP_MD *md5_md = EVP_md5();
	EVP_MD_CTX **ctx_ptr = (EVP_MD_CTX **)ctx;
	*ctx_ptr = EVP_MD_CTX_new();

	if (!EVP_DigestInit_ex2(*ctx_ptr, md5_md, NULL)) {
		fprintf(stdout, "[-] MD5 digest initialization failed.\n");
		EVP_MD_CTX_free(*ctx_ptr);
		*ctx_ptr = NULL;
	}
#else
	MD5_Init(ctx);
#endif
}

static void md5_update(void *ctx, const void *data, size_t len)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD_CTX **ctx_ptr = (EVP_MD_CTX **)ctx;

	if (*ctx_ptr == NULL)
		return;

	if (!EVP_DigestUpdate(*ctx_ptr, data, len)) {
		fprintf(stdout, "[-] Message digest update failed.\n");
		EVP_MD_CTX_free(*ctx_ptr);
		*ctx_ptr = NULL;
	}
#else
	MD5_Update(ctx, data, len);
#endif
}

static void md5_final(unsigned char *md, unsigned int *len, void *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD_CTX **ctx_ptr = (EVP_MD_CTX **)ctx;
	*len = 0;

	if (*ctx_ptr == NULL)
		return;

	if (!EVP_DigestFinal_ex(*ctx_ptr, md, len)) {
		fprintf(stdout, "[-] Message digest finalization failed.\n");
	}
	EVP_MD_CTX_free(*ctx_ptr);
	*ctx_ptr = NULL;
#else
	*len = MD5_DIGEST_SIZE;
	MD5_Final(md, ctx);
#endif
}
#endif

static void parasite_status_signal(pid_t pid, int status)
{
	pthread_mutex_lock(&parasite_watch.lock);
	parasite_watch.changed = 1;
	parasite_watch.status = status;
	pthread_cond_signal(&parasite_watch.cond);
	pthread_mutex_unlock(&parasite_watch.lock);

	if (WIFEXITED(status))
		; /* normal exit */
	else if (WIFSIGNALED(status))
		if (WTERMSIG(status) == SIGKILL)
			printf("[-] parasite killed by SIGKILL\n");
		else
			printf("[i] parasite terminated by signal %d%s\n", WTERMSIG(status), WCOREDUMP(status) ? " (code dumped)" : " ");
	else
		printf("[-] unhandled parasite status %x\n", status);
}

static int parasite_status_wait(int *status)
{
	int ret = 0;
	struct timespec ts;

	while (1) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;

		pthread_mutex_lock(&parasite_watch.lock);
		while (!parasite_watch.changed && (ret == 0 || ret == ETIMEDOUT))
			ret = pthread_cond_timedwait(&parasite_watch.cond, &parasite_watch.lock, &ts);
		if (!ret)
			*status = parasite_watch.status;
		pthread_mutex_unlock(&parasite_watch.lock);

		if (ret != ETIMEDOUT)
			break;

		fprintf(stdout, "[i] waiting for parasite status change\n");
	}

	if (ret)
		fprintf(stderr, "[-] parasite status cond timedwait failed: %d\n", ret);

	pthread_join(parasite_watch.thread_id, NULL);

	return ret;
}

static int parasite_status_ok(void)
{
	int ret;

	pthread_mutex_lock(&parasite_watch.lock);
	ret = !parasite_watch.changed;
	pthread_mutex_unlock(&parasite_watch.lock);

	return ret;
}

static void parasite_socket_init(struct sockaddr_un *addr, pid_t pid)
{
	memset(addr, 0x00, sizeof(struct sockaddr_un));

	addr->sun_family = AF_UNIX;

	if (parasite_socket_dir)
		snprintf(addr->sun_path, sizeof(addr->sun_path), "%s/memcr%u", parasite_socket_dir, pid);
	else {
		snprintf(addr->sun_path, sizeof(addr->sun_path), "#memcr%u", pid);
		addr->sun_path[0] = '\0';
	}
}

static void cleanup_pid(pid_t pid)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/pages-%d.img", dump_dir, pid);
	unlink(path);

	if (!parasite_socket_dir)
		return;

	snprintf(path, sizeof(path), "%s/memcr%u", parasite_socket_dir, pid);
	unlink(path);
}

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
		if (errno == ESRCH) {
			fprintf(stderr, "ptrace(PTRACE_SEIZE) pid %d: %m, ignoring\n", pid);
			return 0;
		}

		fprintf(stderr, "ptrace(PTRACE_SEIZE) %d pid %d: %m\n", errno, pid);
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

static int unseize_pid(pid_t pid)
{
	return ptrace(PTRACE_DETACH, pid, NULL, 0);
}

static int unseize_target(void)
{
	int ret = 0;
	int i;

	printf("[+] unseizing target\n");

	for (i = 0; i < nr_threads; i++)
		ret |= unseize_pid(tids[i]);
	nr_threads = 0;

	return ret;
}

static int parasite_socket_create(pid_t pid)
{
	int pid_netns = -1;
	int cur_netns = -1;
	char netns_path[64];
	int cd;

	if (parasite_socket_use_netns) {
		/* get both current and parasite network namespaces */
		snprintf(netns_path, sizeof(netns_path), "/proc/%d/ns/net", pid);
		pid_netns = open(netns_path, O_CLOEXEC | O_RDONLY);
		if (pid_netns < 0) {
			fprintf(stderr, "open('%s', ) failed: %m\n", netns_path);
		} else {
			cur_netns = open("/proc/self/ns/net", O_CLOEXEC | O_RDONLY);
			if (cur_netns < 0) {
				fprintf(stderr, "open('/proc/self/ns/net', ) failed: %m\n");
				close(pid_netns);
				pid_netns = -1;
			}
		}

		/* switch to network namespace of parasite if available */
		if (pid_netns >= 0) {
			if (setns(pid_netns, CLONE_NEWNET) != 0) {
				fprintf(stderr, "setns() failed: %m\n");
			}
			close(pid_netns);
		}
	}

	cd = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (cd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
	}

	/* restore original network namespace if available */
	if (cur_netns >= 0) {
		if (setns(cur_netns, CLONE_NEWNET) != 0) {
			fprintf(stderr, "setns() failed: %m\n");
		}
		close(cur_netns);
	}

	return cd;
}

static int parasite_connect(pid_t pid)
{
	int cd;
	struct sockaddr_un addr;
	int ret;
	int cnt = 0;

	cd = parasite_socket_create(pid);
	if (cd < 0) {
		return -1;
	}

	parasite_socket_init(&addr, pid);

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
			return -1;
		}
	}

	return cd;
}

static int __read(int fd, void *buf, size_t count, int (*check_peer_ok)(void), int silent)
{
	int ret;
	int off = 0;

	assert(count != 0);

	while (1) {
		ret = read(fd, buf + off, count - off);
		if (ret == 0)
			break;

		if (ret < 0) {
			if (errno == EAGAIN && check_peer_ok) {
				if (check_peer_ok())
					continue;

				break;
			} else if (errno == EINTR) {
				continue;
			}

			if (silent == FALSE)
				fprintf(stderr, "[-] %s() failed: %m\n", __func__);

			break;
		}

		if (ret < count - off) {
			off += ret;
			continue;
		}

		return count;
	}

	return ret;
}

static int __write(int fd, const void *buf, size_t count, int (*check_peer_ok)(void))
{
	int ret;
	int off = 0;

	assert(count != 0);

	while (1) {
		ret = write(fd, buf + off, count - off);
		if (ret < 0) {
			if (errno == EAGAIN && check_peer_ok)
				if (check_peer_ok())
					continue;

			fprintf(stderr, "[-] %s() failed: %m\n", __func__);
			break;
		}

		if (ret < count - off) {
			off += ret;
			continue;
		}

		return count;
	}

	return ret;
}

static int parasite_read(int fd, void *buf, size_t count)
{
	return __read(fd, buf, count, parasite_status_ok, FALSE);
}

static int parasite_write(int fd, const void *buf, size_t count)
{
	return __write(fd, buf, count, parasite_status_ok);
}

static int _read(int fd, void *buf, size_t count)
{
	return __read(fd, buf, count, NULL, FALSE);
}

static int _read_silent(int fd, void *buf, size_t count)
{
	return __read(fd, buf, count, NULL, TRUE);
}

static int _write(int fd, const void *buf, size_t count)
{
	return __write(fd, buf, count, NULL);
}

static int dump_open(const char *pathname, int flags, mode_t mode)
{
	if (lib__open)
		return lib__open(pathname, flags, mode);

	return open(pathname, flags, mode);
}

static int dump_close(int fd)
{
	if (lib__close)
		return lib__close(fd);

	return close(fd);
}

static int dump_read(int fd, void *buf, size_t count)
{
	int ret;

	if (lib__read)
		ret = lib__read(fd, buf, count);
	else
		ret = __read(fd, buf, count, NULL, FALSE);

#ifdef CHECKSUM_MD5
	if (checksum && ret > 0)
		md5_update(&md5_restore_ctx, buf, count);
#endif

	return ret;
}

static int dump_write(int fd, const void *buf, size_t count)
{
	int ret;

	if (lib__write)
		ret = lib__write(fd, buf, count);
	else
		ret = __write(fd, buf, count, NULL);

#ifdef CHECKSUM_MD5
	if (checksum && ret > 0)
		md5_update(&md5_checkpoint_ctx, buf, count);
#endif

	return ret;
}

static void init_pid_checkpoint_data(pid_t pid)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == PID_INVALID) {
			checkpoint_service_data[i].pid = pid;
			checkpoint_service_data[i].worker = PID_INVALID;
			checkpoint_service_data[i].checkpoint_cmd_sd = SOCKET_INVALID;
			checkpoint_service_data[i].state = STATE_RESTORED;
			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	fprintf(stderr, "%s: Checkpoint data PIDs limit exceeded!\n", __func__);
}

static void cleanup_checkpointed_pids(void)
{
	fprintf(stdout, "[i] Terminating checkpointed processes\n");
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid != PID_INVALID) {
			fprintf(stdout, "[i] Killing PID %d\n", checkpoint_service_data[i].pid);
			kill(checkpoint_service_data[i].pid, SIGKILL);
			cleanup_pid(checkpoint_service_data[i].pid);
			checkpoint_service_data[i].pid = PID_INVALID;
			checkpoint_service_data[i].worker = PID_INVALID;
			checkpoint_service_data[i].state = STATE_RESTORED;
			checkpoint_service_data[i].checkpoint_cmd_sd = SOCKET_INVALID;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
}

static void send_checkpoint_abort(int sd)
{
	/* Send MEMCR_RESTORE cmd to worker to abort checkpoint */
	struct service_command cmd;
	cmd.cmd = MEMCR_RESTORE;
	int ret = _write(sd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stdout, "[-] Command abort checkpoint write failed\n");
		return;
	}
}

static void set_pid_checkpointing(pid_t pid, int cmd_sd)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == pid
				&& checkpoint_service_data[i].state == STATE_RESTORED) {
			checkpoint_service_data[i].state = STATE_CHECKPOINTING;
			checkpoint_service_data[i].checkpoint_cmd_sd = cmd_sd;
			if (checkpoint_service_data[i].checkpoint_abort)
				send_checkpoint_abort(cmd_sd);

			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	fprintf(stderr, "%s: PID not found!\n", __func__);
}

static void set_pid_checkpointed(pid_t pid, pid_t worker)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == pid
				&& checkpoint_service_data[i].state == STATE_CHECKPOINTING) {
			checkpoint_service_data[i].state = STATE_CHECKPOINTED;
			checkpoint_service_data[i].checkpoint_cmd_sd = SOCKET_INVALID;
			checkpoint_service_data[i].worker = worker;
			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	fprintf(stderr, "%s: PID not found!\n", __func__);
}

static void clear_pid_checkpoint_data(pid_t pid)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == pid) {
			checkpoint_service_data[i].pid = PID_INVALID;
			checkpoint_service_data[i].worker = PID_INVALID;
			checkpoint_service_data[i].checkpoint_cmd_sd = SOCKET_INVALID;
			checkpoint_service_data[i].state = STATE_RESTORED;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
}

static void clear_pid_on_worker_exit_non_blocking(pid_t worker)
{
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].worker == worker) {
			fprintf(stdout, "[+] Clearing pid: %d with worker: %d on worker exit ...\n",
				checkpoint_service_data[i].pid, worker);
			cleanup_pid(checkpoint_service_data[i].pid);
			checkpoint_service_data[i].pid = PID_INVALID;
			checkpoint_service_data[i].worker = PID_INVALID;
			checkpoint_service_data[i].checkpoint_cmd_sd = SOCKET_INVALID;
			checkpoint_service_data[i].state = STATE_RESTORED;
		}
	}
}

static int get_pid_worker(pid_t pid)
{
	int worker = PID_INVALID;
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == pid) {
			worker = checkpoint_service_data[i].worker;
			break;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	return worker;
}

static int can_checkpoint_pid(pid_t pid)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		/* Check if pid is already in use */
		if (checkpoint_service_data[i].pid == pid) {
			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	return 1;
}

static int can_restore_pid(pid_t pid)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		/* Check if pid is already in use */
		if (checkpoint_service_data[i].pid == pid) {
			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&checkpoint_service_data_lock);
	return 0;
}

static void register_socket_for_checkpoint_service_cmds(int sd)
{
	int flags = fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, flags | O_NONBLOCK);
	checkpoint_service_socket = sd;
}

static void clear_socket_for_checkpoint_service_cmds(void)
{
	checkpoint_service_socket = SOCKET_INVALID;
}

static int is_checkpoint_aborted(void)
{
	if (interrupted)
		return 1;

	if (service) {
		struct service_command svc_cmd;

		if (checkpoint_service_socket == SOCKET_INVALID)
			return 0;

		int ret = _read_silent(checkpoint_service_socket, &svc_cmd, sizeof(svc_cmd));
		if (ret == sizeof(svc_cmd) && svc_cmd.cmd == MEMCR_RESTORE)
			return 1;
	}

	return 0;
}

static int vm_region_valid(const struct vm_region *vmr)
{
	if (vmr->addr & (page_size - 1)) {
		fprintf(stderr, "[-] vm region addr %lx is not page aligned (off by 0x%lx)\n", vmr->addr, vmr->addr & (page_size - 1));
		return 0;
	}

	if (vmr->len % page_size) {
		fprintf(stderr, "[-] vm region len %ld is not multiple of page size %u\n", vmr->len, page_size);
		return 0;
	}

	return 1;
}

static int read_vm_region(int fd, struct vm_region *vmr, char *buf)
{
	int ret;

	ret = dump_read(fd, vmr, sizeof(struct vm_region));
	if (ret != sizeof(struct vm_region))
		return ret;

	if (!vm_region_valid(vmr))
		return -1;

#ifdef COMPRESS_LZ4
	if (compress) {
		int src_size;
		char src[MAX_LZ4_DST_SIZE];

		ret = dump_read(fd, &src_size, sizeof(src_size));
		if (ret != sizeof(src_size))
			return -1;

		ret = dump_read(fd, src, src_size);
		if (ret != src_size)
			return -1;

		ret = LZ4_decompress_safe(src, buf, src_size, MAX_VM_REGION_SIZE);
		/* fprintf(stdout, "[+] Decompressed %d Bytes back into %d.\n", srcSize, ret); */
		if (ret <= 0)
			return -1;
	} else
#endif
	{
		ret = dump_read(fd, buf, vmr->len);
		if (ret != vmr->len)
			return -1;
	}

	return ret;
}

static int write_vm_region(int fd, const struct vm_region *vmr, const void *buf)
{
	int ret;

	if (!vm_region_valid(vmr))
		return -1;

	ret = dump_write(fd, vmr, sizeof(struct vm_region));
	if (ret != sizeof(struct vm_region))
		return -1;

#ifdef COMPRESS_LZ4
	if (compress) {
		char dst[MAX_LZ4_DST_SIZE];
		int dst_size;

		dst_size = LZ4_compress_default(buf, dst, vmr->len, MAX_LZ4_DST_SIZE);
		/* fprintf(stdout, "[+] Compressed %lu Bytes into %d.\n", len, dstSize); */
		if (dst_size <= 0)
			return -1;

		ret = dump_write(fd, &dst_size, sizeof(dst_size));
		if (ret != sizeof(dst_size))
			return -1;

		ret = dump_write(fd, dst, dst_size);
		if (ret != dst_size)
			return -1;

	} else
#endif
	{
		ret = dump_write(fd, buf, vmr->len);
		if (ret != vmr->len)
			return -1;
	}

	return vmr->len;
}

static int setup_listen_socket(struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	int sd;

	sd = socket(addr->sa_family, SOCK_STREAM, 0);
	if (sd < 0) {
		fprintf(stderr, "socket() failed: %m\n");
		return sd;
	}

	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if (ret) {
		fprintf(stderr, "setsockopt() failed: %m\n");
		goto err;
	}

	ret = bind(sd, addr, addrlen);
	if (ret) {
		fprintf(stderr, "bind() failed: %m\n");
		goto err;
	}

	ret = listen(sd, MAX_CLIENT_CONNECTIONS);
	if (ret) {
		fprintf(stderr, "listen() failed: %m\n");
		goto err;
	}

	return sd;

err:
	close(sd);
	return -1;
}

static int setup_listen_unix_socket(const char *client_socket_path)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", client_socket_path);

	fprintf(stdout, "[x] Trying to configure UNIX %s socket.\n", addr.sun_path);
	unlink(addr.sun_path);

	return setup_listen_socket((struct sockaddr *)&addr, sizeof(addr));
}

static int setup_listen_tcp_socket(int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(port),
	};

	fprintf(stdout, "[x] Trying to configure TCP socket on %d port.\n", port);

	return setup_listen_socket((struct sockaddr *)&addr, sizeof(addr));
}

static FILE *fopen_proc(pid_t pid, char *file_name)
{
	FILE *f;
	char path[128];

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, file_name);
	f = fopen(path, "r");
	if (!f)
		fprintf(stderr, "fopen() %s failed: %m\n", path);

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

	if (rss_file)
		printf("[i]   RssFile  %lu kB -> %lu kB (diff %lu kB)\n", a->RssFile, b->RssFile, a->RssFile - b->RssFile);
	else
		printf("[i]   RssFile  %lu kB\n", a->RssFile);

	printf("[i]   RssShmem %lu kB\n", a->RssShmem);
}

static int should_skip_range(unsigned long start, unsigned long end)
{
	return ctx.blob >= (unsigned long *)start && ctx.blob < (unsigned long *)end;
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
	FILE *maps;
	char buf[1024];

	maps = fopen_proc(pid, "maps");
	if (!maps)
		return ret;

	while (fgets(buf, sizeof(buf), maps)) {
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

		/* parasite vma */
		if (should_skip_range(start, end + page_size))
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
	fclose(maps);
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
	if (fd == -1)
		fprintf(stderr, "open() %s failed: %m\n", path);

	return fd;
}

static int target_mprotect(int cd, unsigned long addr, size_t len, unsigned long prot)
{
	int ret;
	struct vm_mprotect req = {
		.addr = addr,
		.len = len,
		.prot = prot,
	};

	ret = parasite_write(cd, &req, sizeof(req));
	if (ret != sizeof(req))
		return -1;

	return 0;
}

static int get_vm_region(int md, int cd, unsigned long addr, unsigned long len, int fd)
{
	int ret;
	unsigned long off;
	char buf[MAX_VM_REGION_SIZE];
	struct vm_region vmr = {
		.addr = addr,
		.len = len,
	};
	struct vm_region_req req;

	if (proc_mem) { /* read region from /proc/pid/mem */
		off = lseek(md, addr, SEEK_SET);
		if (off != addr) {
			fprintf(stderr, "lseek() off %lu: %m\n", off);
			return -1;
		}

		ret = _read(md, &buf, len);
		if (ret != len)
			return -1;
	}

	/* request region from target if needed and madvise */
	req.vmr = vmr;
	req.flags = proc_mem ? 0 : VM_REGION_TX;
	ret = parasite_write(cd, &req, sizeof(req));
	if (ret != sizeof(req))
		return -1;

	if (!proc_mem) {
		/* read requested region */
		ret = parasite_read(cd, &buf, len);
		if (ret != len)
			return -1;
	}

	return write_vm_region(fd, &vmr, buf);
}

static int free_vm_region(int cd, unsigned long addr, unsigned long len)
{
	int ret;
	struct vm_region_req req = {
		.vmr.addr = addr,
		.vmr.len = len,
		.flags = 0,
	};

	ret = parasite_write(cd, &req, sizeof(req));
	if (ret != sizeof(req))
		return -1;

	return 0;
}

static int page_unevictable(uint64_t pfn)
{
	int ret;
	uint64_t flags;

	ret = pread(kpageflags_fd, &flags, sizeof(uint64_t), pfn * sizeof(uint64_t));
	if (ret != sizeof(uint64_t)) {
		fprintf(stderr, "pread() failed: %m\n");
		return 0;
	}

	if (flags & BIT(KPF_UNEVICTABLE))
		return 1;

	return 0;
}

static int get_vma_pages(int pd, int md, int cd, struct vm_area *vma, int fd)
{
	int ret;
	uint64_t off;
	unsigned long nrpages;
	unsigned long idx;
	unsigned long nrpages_dumpable = 0;
	unsigned long nrpages_unevictable = 0;

	unsigned long region_start = 0;
	unsigned long region_length = 0;

	nrpages = (vma->end - vma->start) / page_size;

	idx = vma->start / page_size;
	off = idx * sizeof(uint64_t);
	off = lseek(pd, off, SEEK_SET);
	if (off != idx * sizeof(uint64_t)) {
		fprintf(stderr, "lseek() off %lu: %m\n", (unsigned long)off);
		return -1;
	}

	for (idx = 0; idx < nrpages; idx++) {
		uint64_t map;
		unsigned long addr;

		addr = vma->start + idx * page_size;

		ret = read(pd, &map, sizeof(map));
		if (ret != sizeof(map)) {
			fprintf(stderr, "read() %m\n");
			continue;
		}

		if (vma->flags & (FLAG_ANON | FLAG_HEAP | FLAG_STACK)) {
			if (map & (BIT(PM_PAGE_PRESENT) | BIT(PM_PAGE_SWAPPED))) {
				nrpages_dumpable++;

				if (map & (BIT(PM_PAGE_PRESENT))) {
					uint64_t pfn = map & PM_PAGE_FRAME_NUMBER_MASK;

					ret = page_unevictable(pfn);
					if (ret) {
						nrpages_unevictable++;
						continue;
					}
				}

				if (!region_start)
					region_start = addr;

				region_length += page_size;

				if ((idx + 1) < nrpages && region_length < MAX_VM_REGION_SIZE)
					continue;
			}

			if (!region_start)
				continue;

			ret = get_vm_region(md, cd, region_start, region_length, fd);
			if (ret <= 0)
				return ret;

			region_start = 0;
			region_length = 0;
			continue;
		}

		if (rss_file && vma->flags & FLAG_FILE) {
			if (map & BIT(PM_PAGE_FILE_OR_SHARED_ANON)) {
				nrpages_dumpable++;

				if (!region_start)
					region_start = addr;

				region_length += page_size;

				if ((idx + 1) < nrpages)
					continue;

			}

			if (!region_start)
				continue;

			ret = free_vm_region(cd, region_start, region_length);
			if (ret)
				return ret;

			region_start = 0;
			region_length = 0;
			continue;
		}
	}

	if (nrpages_dumpable) {
		fprintf(stdout, "[i]   %0*lx..%0*lx  %s %6ld kB", 2 * (int)sizeof(unsigned long), vma->start, 2 * (int)sizeof(unsigned long), vma->end, flag_desc[vma->flags], (nrpages_dumpable * page_size) / 1024);
		if (nrpages_unevictable)
			fprintf(stdout, " (unevictable %ld kB)", (nrpages_unevictable * page_size) / 1024);
		fprintf(stdout, "\n");
	}

	return 0;
}

static int get_target_pages(int pid, struct vm_area vmas[], int nr_vmas)
{
	int ret = -1;
	char path[PATH_MAX];
	int pd = -1;
	int fd = -1;
	int md = -1;
	int cd = -1;
	int idx;

	pd = open_proc(pid, "pagemap");
	if (pd < 0)
		goto out;

	snprintf(path, sizeof(path), "%s/pages-%d.img", dump_dir, pid);

	fd = dump_open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "%s() open failed with: %m\n", __func__);
		return -1;
	}

	if (proc_mem) {
		md = open_proc(pid, "mem");
		if (md < 0)
			goto out;
	}

	cd = parasite_connect(pid);
	if (cd < 0) {
		ret = -1;
		goto out;
	}

	ret = parasite_write(cd, &(char){CMD_GET_PAGES}, 1);
	if (ret != 1) {
		ret = -1;
		goto out;
	}

	ret = 0;

	for (idx = 0; idx < nr_vmas; idx++) {
		if (is_checkpoint_aborted()) {
			fprintf(stdout, "[i] get target pages aborted\n");
			break;
		}

		struct vm_area *vma = &vmas[idx];
		ret = get_vma_pages(pd, md, cd, vma, fd);
		if (ret)
			break;
	}

out:
	close(cd);
	close(md);
	dump_close(fd);
	close(pd);
	return ret;
}

static int target_mprotect_off(int pid)
{
	int ret;
	int cd;
	int idx;
	struct vm_area *vma;

	cd = parasite_connect(pid);
	if (cd < 0)
		return cd;

	ret = parasite_write(cd, &(char){CMD_MPROTECT}, 1);
	if (ret != 1) {
		close(cd);
		return -1;
	}

	for (idx = 0; idx < nr_vmas; idx++) {
		vma = &vmas[idx];

		if ((vma->prot & PROT_READ) && (vma->prot & PROT_WRITE))
			continue;

		ret = target_mprotect(cd, vma->start, vma->end - vma->start, vma->prot | PROT_READ | PROT_WRITE);
		if (ret)
			break;
	}

	close(cd);
	return ret;
}

static int target_mprotect_on(int pid)
{
	int ret;
	int cd;
	int idx;
	struct vm_area *vma;

	cd = parasite_connect(pid);
	if (cd < 0)
		return cd;

	ret = parasite_write(cd, &(char){CMD_MPROTECT}, 1);
	if (ret != 1) {
		close(cd);
		return -1;
	}

	for (idx = 0; idx < nr_vmas; idx++) {
		vma = &vmas[idx];

		if ((vma->prot & PROT_READ) && (vma->prot & PROT_WRITE))
			continue;

		ret = target_mprotect(cd, vma->start, vma->end - vma->start, vma->prot);
		if (ret)
			break;
	}

	close(cd);
	return ret;
}

static int target_set_pages(pid_t pid)
{
	int ret;
	char path[PATH_MAX];
	int cd = -1;
	int fd = -1;

	snprintf(path, sizeof(path), "%s/pages-%d.img", dump_dir, pid);

	fd = dump_open(path, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "[-] %s() open failed with: %m\n", __func__);
		return -1;
	}

	cd = parasite_connect(pid);
	if (cd < 0) {
		ret = -1;
		goto out;
	}

	ret = parasite_write(cd, &(char){CMD_SET_PAGES}, 1);
	if (ret != 1) {
		ret = -1;
		goto out;
	}

	while (1) {
		struct vm_region vmr;
		struct vm_region_req req;
		char buf[MAX_VM_REGION_SIZE];

		ret = read_vm_region(fd, &vmr, buf);
		if (ret <= 0)
			break;

		req.vmr = vmr;
		req.flags = 0;

		ret = parasite_write(cd, &req, sizeof(req));
		if (ret != sizeof(req)) {
			ret = -1;
			break;
		}

		ret = parasite_write(cd, &buf, vmr.len);
		if (ret != vmr.len) {
			ret = -1;
			break;
		}
	}

out:
	close(cd);
	dump_close(fd);
	return ret;
}

static int target_cmd_end(int pid)
{
	int ret;
	int cd;

	cd = parasite_connect(pid);
	if (cd < 0)
		return -1;

	ret = parasite_write(cd, &(char){CMD_END}, 1);
	if (ret != 1)
		ret = -1;

	close(cd);
	return ret;
}

static long diff_ms(struct timespec *ts)
{
	struct timespec tsn;

	clock_gettime(CLOCK_MONOTONIC, &tsn);

	return (tsn.tv_sec*1000 + tsn.tv_nsec/1000000) - (ts->tv_sec*1000 + ts->tv_nsec/1000000);
}

static int cmd_checkpoint(pid_t pid)
{
	int ret;
	struct vm_stats vms_a, vms_b;
	struct timespec ts;

	if (parasite_pid != parasite_pid_clone)
		fprintf(stdout, "[i] parasite pid %d (namespace pid %d)\n", parasite_pid, parasite_pid_clone);
	else
		fprintf(stdout, "[i] parasite pid %d\n", parasite_pid);

	ret = scan_target_vmas(pid, vmas, &nr_vmas);
	if (ret) {
		fprintf(stderr, "[-] scan_target_vmas() failed: ret %d\n", ret);
		return 1;
	}

	get_target_rss(pid, &vms_a);

	print_target_vmas(vmas, nr_vmas, vms_a.VmRSS);

	fprintf(stdout, "[+] mprotect off\n");
	target_mprotect_off(pid);

#ifdef CHECKSUM_MD5
	if (checksum)
		md5_init(&md5_checkpoint_ctx);
#endif

	fprintf(stdout, "[+] downloading pages\n");
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ret = get_target_pages(pid, vmas, nr_vmas);

#ifdef CHECKSUM_MD5
	if (checksum)
		md5_final(md5_checkpoint_digest, &md5_checkpoint_digest_len, &md5_checkpoint_ctx);
#endif

	if (ret) {
		fprintf(stderr, "get_target_pages() failed\n");
		return ret;
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

	if (!parasite_status_ok()) {
		return 1;
	}

#ifdef CHECKSUM_MD5
	if (checksum)
		md5_init(&md5_restore_ctx);
#endif

	fprintf(stdout, "[+] uploading pages\n");
	clock_gettime(CLOCK_MONOTONIC, &ts);
	target_set_pages(pid);
	fprintf(stdout, "[i] upload took %lu ms\n", diff_ms(&ts));

#ifdef CHECKSUM_MD5
	if (checksum) {
		md5_final(md5_restore_digest, &md5_restore_digest_len, &md5_restore_ctx);
		unsigned char *b = md5_checkpoint_digest;
		fprintf(stdout, "[+] checkpoint crc: ");
		for (unsigned int i=0; i<md5_checkpoint_digest_len; ++i)
			fprintf(stdout, "%X ", b[i]);

		fprintf(stdout, "\n");

		b = md5_restore_digest;
		fprintf(stdout, "[+] restore crc: ");
		for (unsigned int i=0; i<md5_restore_digest_len; ++i)
			fprintf(stdout, "%X ", b[i]);

		fprintf(stdout, "\n");

		if ( (md5_checkpoint_digest_len == 0)
			|| (md5_restore_digest_len == 0)
			|| (md5_checkpoint_digest_len != md5_restore_digest_len)
			|| (memcmp(md5_checkpoint_digest, md5_restore_digest, md5_restore_digest_len) != 0) ) {
			printf("[-] dump checksum do not match!\n");

			fprintf(stderr, "[%d] Restore failed! Killing the target app...\n", getpid());
			kill(pid, SIGKILL);
			return 1;
		}
	}
#endif

	fprintf(stdout, "[+] mprotect on\n");
	target_mprotect_on(pid);

	/*
	 * This is needed to avoid a race between freezer and target when target sets up its memory
	 * and freezer can unseize too early. To achieve that we send one more command that will be
	 * handled once previous one (set pages) is done.
	 */
	target_cmd_end(pid);

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

static int peek(pid_t pid, unsigned long *addr, unsigned long *dst, size_t len)
{
	int i;

	/* len must be a multiple of CPU word size */
	assert(len % sizeof(unsigned long) == 0);

	for (i = 0; i < (len / sizeof(unsigned long)); i++) {
		errno = 0;
		dst[i] = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
		if (errno) {
			fprintf(stderr, "[-] %s() failed addr %p, dst %p, i %d: %m\n", __func__, addr, dst, i);
			return errno;
		}
	}

	return 0;
}

static int poke(pid_t pid, unsigned long *addr, unsigned long *src, size_t len)
{
	int ret;
	int i;

	/* len must be a multiple of CPU word size */
	assert(len % sizeof(unsigned long) == 0);

	for (i = 0; i < (len / sizeof(unsigned long)); i++) {
		ret = ptrace(PTRACE_POKEDATA, pid, addr + i, *(src + i));
		if (ret) {
			fprintf(stderr, "[-] %s() failed addr %p, src %p, i %d: %m\n", __func__, addr, src, i);
			break;
		}
	}

	return ret;
}

static unsigned long execute_blob(struct target_context *ctx, const char *blob, size_t size, unsigned long arg0, unsigned long arg1)
{
	unsigned long stack[2]; /* used for sigset only */
	struct registers regs, saved_regs;
	siginfo_t si;
	int status;

	/* inject blob into the host */
	poke(ctx->pid, ctx->pc, (unsigned long *)blob, size);

	/* save stack and regs */
	peek(ctx->pid, ctx->sp, (unsigned long *)&stack, sizeof(stack));
	read_cpu_regs(ctx->pid, &saved_regs);

retry:
	regs = saved_regs;
	set_cpu_regs(&regs, ctx->pc, arg0, arg1);
	write_cpu_regs(ctx->pid, &regs);

	/* let the blob run, upon completion it will trigger debug trap */
	assert(!ptrace(PTRACE_CONT, ctx->pid, NULL, NULL));
	assert(wait4(ctx->pid, &status, __WALL, NULL) == ctx->pid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, ctx->pid, NULL, &si));

	if (WSTOPSIG(status) != SIGTRAP || SI_FROMUSER(&si)) {
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
		 * control returns to jobctl trap.
		 *
		 * Note that if signal is delivered between syscall and the
		 * trapping instruction in the blob, the syscall might be
		 * executed again. Block signals first before doing any
		 * operation with side effects.
		 */
	retry_signal:
		printf("[i] delivering signal %d si_code %d\n", si.si_signo, si.si_code);

		write_cpu_regs(ctx->pid, &saved_regs);

		assert(!ptrace(PTRACE_INTERRUPT, ctx->pid, NULL, NULL));
		assert(!ptrace(PTRACE_CONT, ctx->pid, NULL, (void *)(unsigned long)si.si_signo));

		/* wait for trap */
		assert(wait4(ctx->pid, &status, __WALL, NULL) == ctx->pid);
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "[-] target pid %d terminated by signal %d%s\n", ctx->pid, WTERMSIG(status), WCOREDUMP(status) ? " (core dumped)" : " ");
			return -1;
		}

		assert(WIFSTOPPED(status));
		assert(!ptrace(PTRACE_GETSIGINFO, ctx->pid, NULL, &si));

		/* are we back at jobctl trap or are there more signals? */
		if (SI_EVENT(si.si_code) != PTRACE_EVENT_STOP)
			goto retry_signal;

		/* restore stack */
		poke(ctx->pid, ctx->sp, (unsigned long *)&stack, sizeof(stack));

		/* otherwise, retry */
		goto retry;
	}

	/*
	 * Okay, this is the SIGTRAP delivery from the trapping instruction. Steer the thread
	 * back to jobctl trap by raising INTERRUPT and squashing SIGTRAP.
	 */
	assert(!ptrace(PTRACE_INTERRUPT, ctx->pid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, ctx->pid, NULL, NULL));

	assert(wait4(ctx->pid, &status, __WALL, NULL) == ctx->pid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, ctx->pid, NULL, &si));
	assert(SI_EVENT(si.si_code) == PTRACE_EVENT_STOP);

	/* retrieve return value and restore registers */
	read_cpu_regs(ctx->pid, &regs);
	write_cpu_regs(ctx->pid, &saved_regs);

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
	unsigned long *src = (unsigned long *)&pa;
	unsigned long *dst = (unsigned long *)PARASITE_ARGS_ADDR(base);

	parasite_socket_init(&pa.addr, pid);

	return poke(pid, dst, src, sizeof(pa));
}

static void *parasite_watch_thread(void *ptr)
{
	int ret;
	unsigned long pid = (unsigned long)ptr;
	int status;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		fprintf(stderr, "[-] seize of %ld failed: %m\n", pid);
		/* TODO */
		return NULL;
	}

	printf("[+] watching parasite %ld\n", pid);

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret != pid) {
		fprintf(stderr, "[-] wait4() ret %d != parasite %ld, errno %m\n", ret, pid);
		return NULL;
	}

	parasite_status_signal(pid, status);

	return NULL;
}

static int parasite_watch_start(pid_t pid)
{
	int ret;

	ret = pthread_create(&parasite_watch.thread_id, NULL, parasite_watch_thread, (void *)(unsigned long)pid);
	if (ret)
		fprintf(stderr, "[-] pthread_create() failed: %d\n", ret);

	return ret;
}

static int signals_block(pid_t pid)
{
	long ret;
	uint64_t sigset_new;
	uint64_t sigset_old;

	assert(pid == ctx.pid);

	printf("[+] blocking signals\n");
	sigset_new = -1;
	poke(ctx.pid, ctx.sp, (unsigned long *)&sigset_new, sizeof(sigset_new));
	ret = execute_blob(&ctx, sigprocmask_blob, sigprocmask_blob_size, (unsigned long)ctx.sp, 0);
	peek(ctx.pid, ctx.sp, (unsigned long *)&sigset_old, sizeof(sigset_old));
#if DEBUG_SIGSET
	printf(" = %#lx, %016" PRIx64 " -> %016" PRIx64 "\n", ret, sigset_old, sigset_new);
#endif
	ctx.sigset = sigset_old;
	assert(!ret);

	return ret;
}

static int signals_unblock(pid_t pid)
{
	long ret;
	uint64_t sigset_new;
#if DEBUG_SIGSET
	uint64_t sigset_old;
#endif

	assert(pid == ctx.pid);

	printf("[+] unblocking signals\n");
	sigset_new = ctx.sigset;
	poke(ctx.pid, ctx.sp, (unsigned long *)&sigset_new, sizeof(sigset_new));
	ret = execute_blob(&ctx, sigprocmask_blob, sigprocmask_blob_size, (unsigned long)ctx.sp, 0);
	if (ret)
		return ret;
#if DEBUG_SIGSET
	peek(pid, ctx.sp, (unsigned long *)&sigset_old, sizeof(sigset_old));
	printf(" = %#lx, %016" PRIx64 " -> %016" PRIx64 "\n", ret, sigset_old, sigset_new);
#endif

	return 0;
}

static int ctx_save(pid_t pid)
{
	int max_blob_size;
	struct registers regs;

	ctx.pid = pid;

	/* allocate space to save original code */
	max_blob_size = MAX(sigprocmask_blob_size, MAX(mmap_blob_size, MAX(clone_blob_size, munmap_blob_size)));
	ctx.code_size = DIV_ROUND_UP(max_blob_size, sizeof(unsigned long)) * sizeof(unsigned long);

	ctx.code = malloc(ctx.code_size);
	assert(ctx.code);

	read_cpu_regs(ctx.pid, &regs);

	/*
	 * The page %ip is on gotta be executable. If we inject from the
	 * beginning of the page, there should be at least one page of
	 * space. Determine the position and save the original code.
	 */
	ctx.pc = (void *)round_down((unsigned long)get_cpu_regs_pc(&regs), page_size);
	peek(ctx.pid, ctx.pc, ctx.code, ctx.code_size);

	/*
	 * Save and restore some bytes below %sp so that blobs can use it
	 * as writeable scratch area. This wouldn't be necessary if mmap
	 * is done earlier.
	 */
	ctx.sp = get_cpu_regs_sp(&regs) - sizeof(ctx.stack);
	peek(ctx.pid, ctx.sp, ctx.stack, sizeof(ctx.stack));

	return 0;
}

static int ctx_restore(pid_t pid)
{
	assert(pid == ctx.pid);

	/* restore the original code and stack area */
	poke(ctx.pid, ctx.pc, ctx.code, ctx.code_size);
	poke(ctx.pid, ctx.sp, ctx.stack, sizeof(ctx.stack));
	free(ctx.code);

	return 0;
}

static int execute_parasite_checkpoint(pid_t pid)
{
	unsigned long ret;

	ctx_save(pid);

	signals_block(pid);

	/* mmap space for parasite */
	ret = execute_blob(&ctx, mmap_blob, mmap_blob_size, sizeof(parasite_blob), 0);
	if (ret >= -4096LU) {
		fprintf(stdout, "[-] mmap failed: %lx\n", ret);
		signals_unblock(pid);
		ctx_restore(pid);
		return -1;
	}

	/* copy parasite_blob into the mmapped area */
	ctx.blob = (void *)ret;
	poke(pid, ctx.blob, (unsigned long *)parasite_blob, sizeof(parasite_blob));

	setup_parasite_args(pid, ctx.blob);

	/* clone parasite which will trap and wait for instruction */
	ret = execute_blob(&ctx, clone_blob, clone_blob_size, (unsigned long)ctx.blob, 0);
	assert(ret > 0);
	parasite_pid_clone = ret;

	/* translate lxc ns pid to global one */
	iterate_pstree(pid, 0, MAX_THREADS, update_parasite_pid);

	parasite_watch_start(parasite_pid);

	ret = cmd_checkpoint(pid);
	return ret;
}

static int execute_parasite_restore(pid_t pid)
{
	unsigned long ret;
	int status;

	cmd_restore(pid);

	parasite_status_wait(&status);

	/* parasite was terminated by a signal */
	if (WIFSIGNALED(status))
		return 1;

	assert(WIFEXITED(status) == 1);

	/* parasite is done, munmap parasite_blob area */
	ret = execute_blob(&ctx, munmap_blob, munmap_blob_size, (unsigned long)ctx.blob, sizeof(parasite_blob));
	if (ret)
		fprintf(stderr, "[-] munmap failed: %ld\n", ret);

	signals_unblock(pid);

	ctx_restore(pid);

	return 0;
}

static void sigint_handler(int signal)
{
	const char *msg = "[i] SIGINT\n";

	interrupted = 1;
	write(1, msg, strlen(msg));
}

static void sigchld_handler_service(int sig, siginfo_t *sip, void *notused)
{
	int status;
	int _errno;
	pid_t pid;

	_errno = errno;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		clear_pid_on_worker_exit_non_blocking(pid);
	}

	errno = _errno;
}

static void sigchld_handler_worker(int signal)
{
	pid_t pid;
	int   status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		fprintf(stdout, "[%d] SIHCHLD received for %d...\n", getpid(), pid);
	}
	fprintf(stdout, "[%d] Tracee killed, worker exit!\n", getpid());
	exit(0);
}

static void sigpipe_handler(int sig, siginfo_t *sip, void *notused)
{
	fprintf(stdout, "[!] program received SIGPIPE from %d.\n", sip->si_pid);
}

static int read_command(int cd, struct service_command *svc_cmd)
{
	int ret;

	ret = _read(cd, svc_cmd, sizeof(struct service_command));
	if (ret != sizeof(struct service_command)) {
		fprintf(stderr, "[-] %s(): ret %d, errno %m\n", __func__, ret);
		return -1;
	}

	return ret;
}

static int send_response_to_client(int cd, memcr_svc_response resp_code)
{
	struct service_response svc_resp = { .resp_code = resp_code };
	int ret;

	ret = _write(cd, &svc_resp, sizeof(svc_resp));
	if (ret != sizeof(svc_resp)) {
		fprintf(stderr, "[-] %s(): error sending response!\n", __func__);
		return -1;
	}

	return 0;
}

static int send_response_to_service(int fd, int status)
{
	int ret;
	struct service_response svc_resp;

	svc_resp.resp_code = status ? MEMCR_ERROR_GENERAL : MEMCR_OK;

	fprintf(stdout, "[%d] Sending %s response.\n", getpid(), (status ? "ERROR" : "OK"));
	ret = _write(fd, &svc_resp, sizeof(struct service_response));
	if (ret != sizeof(svc_resp))
		return -1;

	return 0;
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

static int checkpoint_worker(pid_t pid)
{
	int ret;

	ret = seize_target(pid);
	if (ret)
		return ret;

	ret = execute_parasite_checkpoint(pid);
	if (ret) {
		fprintf(stderr, "[%d] Parasite checkpoint failed! Killing the target app...\n", getpid());
		kill(pid, SIGKILL);
		cleanup_pid(pid);
		return ret;
	}

	signal(SIGCHLD, sigchld_handler_worker);
	return 0;
}

static int restore_worker(int rd)
{
	int ret;
	struct service_command post_checkpoint_cmd;

	ret = read_command(rd, &post_checkpoint_cmd);

	if (ret < 0 || MEMCR_RESTORE != post_checkpoint_cmd.cmd) {
		fprintf(stdout, "[%d] Error reading restore command!\n", getpid());
		return -1;
	}

	fprintf(stdout, "[%d] Worker received RESTORE command for %d.\n", getpid(), post_checkpoint_cmd.pid);

	signal(SIGCHLD, SIG_DFL);
	ret = execute_parasite_restore(post_checkpoint_cmd.pid);
	unseize_target();
	cleanup_pid(post_checkpoint_cmd.pid);

	return ret;
}

static int application_worker(pid_t pid, int checkpoint_resp_socket)
{
	int rsd, rd, ret = 0;

	fprintf(stdout, "[%d] memcr worker is started to checkpoint %d.\n", getpid(), pid);

	rsd = setup_restore_socket_worker(pid);
	if (rsd < 0)
		ret |= rsd;

	register_socket_for_checkpoint_service_cmds(checkpoint_resp_socket);

	if (0 == ret) {
		ret |= checkpoint_worker(pid);
	}
	ret |= send_response_to_service(checkpoint_resp_socket, ret); // send resp to service
	clear_socket_for_checkpoint_service_cmds();
	close(checkpoint_resp_socket);

	if (ret) {
		fprintf(stderr, "[%d] Process %d checkpoint failed! Aborting procedure.\n", getpid(), pid);
		close(rsd);
		return ret;
	}

	fprintf(stdout, "[%d] Waiting for restore command...\n", getpid());
	rd = accept(rsd, NULL, NULL);
	if (rd < 0) {
		fprintf(stderr, "%s() failed on socket accept.\n", __func__);
		close(rsd);
		return rd;
	}

	ret = restore_worker(rd);
	ret |= send_response_to_service(rd, ret);

	close(rsd);
	close(rd);
	fprintf(stdout, "[%d] Worker ends.\n", getpid());

	return ret;
}

static void try_to_abort_checkpoint(pid_t pid)
{
	pthread_mutex_lock(&checkpoint_service_data_lock);
	for (int i=0; i<CHECKPOINTED_PIDS_LIMIT; ++i) {
		if (checkpoint_service_data[i].pid == pid) {
			switch (checkpoint_service_data[i].state) {
				case STATE_RESTORED:
					/* checkpoint not yet handled, set abort flag only */
					checkpoint_service_data[i].checkpoint_abort = TRUE;
					fprintf(stdout, "[+] Checkpoint cmd pending, abort requested for: %d\n", pid);
					break;
				case STATE_CHECKPOINTING:
					/* checkpoint ongoing, sent abort cmd */
					send_checkpoint_abort(checkpoint_service_data[i].checkpoint_cmd_sd);
					fprintf(stdout, "[+] Checkpoint ongoing, abort requested for: %d\n", pid);
					break;
				case STATE_CHECKPOINTED:
				default:
					/* nothing to abort */
					fprintf(stdout, "[+] Nothing to abort\n");
			}
			pthread_mutex_unlock(&checkpoint_service_data_lock);
			return;
		}
	}
}

static int checkpoint_procedure_service(int checkpointSocket, int cd, int pid, int worker_pid)
{
	int ret;
	struct service_response svc_resp;

	if (timeout) {
		fprintf(stdout, "[+] Service waiting for worker checkpoint with timeout %d[s]...\n", timeout);
		struct timeval rcv_timeout = { .tv_sec = timeout, .tv_usec = 0 };
		ret = setsockopt(checkpointSocket, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));
		if (ret < 0)
			fprintf(stderr, "[-] Error setting socket timeout: %m, waiting forever!\n");
	} else
		fprintf(stdout, "[+] Service waiting for worker checkpoint...\n");

	ret = _read(checkpointSocket, &svc_resp, sizeof(svc_resp)); // receive resp from child

	if (ret == sizeof(svc_resp)) {
		fprintf(stdout, "[+] Service received checkpoint response, informing client...\n");
		send_response_to_client(cd, svc_resp.resp_code);
		return svc_resp.resp_code;
	} else {
		fprintf(stderr, "[!] Error reading checkpoint response from worker!\n");
		// unable to read response from worker, kill both
		kill(pid, SIGKILL);
		kill(worker_pid, SIGKILL);
		cleanup_pid(pid);
		send_response_to_client(cd, MEMCR_ERROR_GENERAL);
		return MEMCR_ERROR_GENERAL;
	}
}

static void restore_procedure_service(int cd, struct service_command svc_cmd, int worker_pid)
{
	int rd, ret = 0;
	struct service_response svc_resp;

	rd = setup_restore_socket_service(svc_cmd.pid);
	if (rd < 0) {
		fprintf(stderr, "[!] Error in setup restore connection to worker!\n");
		ret = -1;
	}

	ret = _write(rd, &svc_cmd, sizeof(struct service_command)); // send restore to service
	if (ret != sizeof(struct service_command)) {
		fprintf(stderr, "[-] %s() write() svc_cmd failed: ret %d\n", __func__, ret);
		ret = -1;
	}

	if (timeout) {
		fprintf(stdout, "[+] Service waiting for worker to restore with timeout %d[s]...\n", timeout);
		struct timeval rcv_timeout = { .tv_sec = timeout, .tv_usec = 0 };
		ret = setsockopt(rd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));
		if (ret < 0)
			fprintf(stderr, "[-] Error setting socket timeout: %m, waiting forever!\n");
	} else
		fprintf(stdout, "[+] Service waiting for worker to restore... \n");

	ret = _read(rd, &svc_resp, sizeof(struct service_response));   // read response from service
	close(rd);

	if (ret != sizeof(struct service_response)) {
		fprintf(stderr, "[-] %s() read() svc_resp failed: ret %d\n", __func__, ret);
		// unable to read response from worker, kill both
		kill(svc_cmd.pid, SIGKILL);
		kill(worker_pid, SIGKILL);
		cleanup_pid(svc_cmd.pid);
		ret = -1;
	}

	if (-1 == ret || MEMCR_OK != svc_resp.resp_code) {
		fprintf(stderr, "[!] There were errors during restore procedure, sending ERROR response to client!\n");
		send_response_to_client(cd, MEMCR_ERROR_GENERAL);
	} else {
		fprintf(stdout, "[i] Restore procedure finished. Sending OK response to client.\n");
		send_response_to_client(cd, MEMCR_OK);
	}
}

static void register_signal_handlers(void)
{
	struct sigaction sigchld_action, sigpipe_action;

	sigchld_action.sa_sigaction = sigchld_handler_service;
	sigfillset(&sigchld_action.sa_mask);
	sigchld_action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESTART;

	sigpipe_action.sa_sigaction = sigpipe_handler;
	sigfillset(&sigpipe_action.sa_mask);
	sigpipe_action.sa_flags = SA_SIGINFO;

	sigaction(SIGCHLD, &sigchld_action, NULL);
	sigaction(SIGPIPE, &sigpipe_action, NULL);
	signal(SIGINT, sigint_handler);
}

static void *service_command_thread(void *ptr)
{
	int ret;
	struct service_command_ctx svc_ctx = {};

retry:

	ret = service_cmds_wait_and_pop_front(&svc_ctx);
	if (ret) {
		fprintf(stdout, "[+] Service cmd thread finished\n");
		return NULL;
	}

	switch (svc_ctx.svc_cmd.cmd) {
		case MEMCR_CHECKPOINT: {
			fprintf(stdout, "[+] handling MEMCR_CHECKPOINT for %d.\n", svc_ctx.svc_cmd.pid);

			int checkpoint_resp_sockets[2];
			ret = socketpair(AF_UNIX, SOCK_STREAM, 0, checkpoint_resp_sockets);
			if (ret < 0) {
				fprintf(stderr, "%s(): Error in socketpair creation!\n", __func__);
				return NULL;
			}

			pid_t forkpid = fork();
			if (0 == forkpid) {
				close(svc_ctx.cd);
				close(checkpoint_resp_sockets[0]);

				ret = application_worker(svc_ctx.svc_cmd.pid, checkpoint_resp_sockets[1]);
				exit(ret);
			} else if (forkpid > 0) {
				close(checkpoint_resp_sockets[1]);
				set_pid_checkpointing(svc_ctx.svc_cmd.pid, checkpoint_resp_sockets[0]);
				if (checkpoint_procedure_service(checkpoint_resp_sockets[0], svc_ctx.cd,
						svc_ctx.svc_cmd.pid, forkpid))
					clear_pid_checkpoint_data(svc_ctx.svc_cmd.pid);
				else
					set_pid_checkpointed(svc_ctx.svc_cmd.pid, forkpid);

				close(checkpoint_resp_sockets[0]);
			} else {
				fprintf(stderr, "%s(): Fork error!\n", __func__);
				clear_pid_checkpoint_data(svc_ctx.svc_cmd.pid);
			}

			break;
		}
		case MEMCR_RESTORE: {
			fprintf(stdout, "[+] handling MEMCR_RESTORE for %d.\n", svc_ctx.svc_cmd.pid);
			int worker_pid = get_pid_worker(svc_ctx.svc_cmd.pid);
			if (worker_pid == PID_INVALID) {
				fprintf(stderr, "%s(): Error, worker pid not found for %d!\n", __func__, svc_ctx.svc_cmd.pid);
				send_response_to_client(svc_ctx.cd, MEMCR_ERROR_GENERAL);
				close(svc_ctx.cd);
				break;
			}
			restore_procedure_service(svc_ctx.cd, svc_ctx.svc_cmd, worker_pid);
			clear_pid_checkpoint_data(svc_ctx.svc_cmd.pid);
			break;
		}
		default:
			fprintf(stderr, "%s() unexpected command %d\n", __func__, svc_ctx.svc_cmd.cmd);
			break;
	}

	close(svc_ctx.cd);
	fprintf(stdout, "[+] cmd handled for %d. \n", svc_ctx.svc_cmd.pid);

	goto retry;
}

static void service_command(struct service_command_ctx *svc_ctx)
{
	int ret = MEMCR_OK;
	switch (svc_ctx->svc_cmd.cmd)
	{
	case MEMCR_CHECKPOINT:
	{
		fprintf(stdout, "[+] got MEMCR_CHECKPOINT for %d.\n", svc_ctx->svc_cmd.pid);

		if (!can_checkpoint_pid(svc_ctx->svc_cmd.pid))
		{
			fprintf(stdout, "[i] Process %d is already checkpointed or checkpoint is ongoing!\n", svc_ctx->svc_cmd.pid);
			send_response_to_client(svc_ctx->cd, MEMCR_INVALID_PID);
			close(svc_ctx->cd);
			break;
		}

		init_pid_checkpoint_data(svc_ctx->svc_cmd.pid);
		ret = service_cmds_push_back(svc_ctx);
		if (!ret)
			fprintf(stdout, "[+] Checkpoint request scheduled...\n");
		else {
			fprintf(stdout, "[+] Checkpoint request schedule error.\n");
			clear_pid_checkpoint_data(svc_ctx->svc_cmd.pid);
			send_response_to_client(svc_ctx->cd, MEMCR_ERROR_GENERAL);
			close(svc_ctx->cd);
		}
		break;
	}
	case MEMCR_RESTORE:
	{
		fprintf(stdout, "[+] got MEMCR_RESTORE for %d.\n", svc_ctx->svc_cmd.pid);

		if (!can_restore_pid(svc_ctx->svc_cmd.pid))
		{
			fprintf(stdout, "[i] Process %d is not checkpointed!\n", svc_ctx->svc_cmd.pid);
			send_response_to_client(svc_ctx->cd, MEMCR_INVALID_PID);
			close(svc_ctx->cd);
			break;
		}

		try_to_abort_checkpoint(svc_ctx->svc_cmd.pid);
		int ret = service_cmds_push_back(svc_ctx);
		if (!ret)
			fprintf(stdout, "[+] Restore request scheduled...\n");
		else {
			fprintf(stdout, "[+] Restore request schedule error.\n");
			send_response_to_client(svc_ctx->cd, MEMCR_ERROR_GENERAL);
			close(svc_ctx->cd);
		}
		break;
	}
	default:
		fprintf(stderr, "%s() unexpected command %d\n", __func__, svc_ctx->svc_cmd.cmd);
		send_response_to_client(svc_ctx->cd, MEMCR_ERROR_GENERAL);
		close(svc_ctx->cd);
		break;
	}
}

static int service_mode(const char *listen_location)
{
	int ret;
	int csd, cd;
	int listen_port = atoi(listen_location);
	int flags;
	fd_set readfds;
	struct timeval tv;
	int errsv;
	pthread_t svc_cmd_thread_id;

	if (listen_port > 0)
		csd = setup_listen_tcp_socket(listen_port);
	else
		csd = setup_listen_unix_socket(listen_location);

	if (csd < 0)
		return -1;

	flags = fcntl(csd, F_GETFL);
	fcntl(csd, F_SETFL, flags | O_NONBLOCK);

	ret = pthread_create(&svc_cmd_thread_id, NULL, service_command_thread, NULL);
	if (ret) {
		fprintf(stderr, "[-] pthread_create() failed: %d\n", ret);
		goto err;
	}

	fprintf(stdout, "[x] Waiting for a checkpoint command on a socket\n");

	while (!interrupted) {
		FD_ZERO(&readfds);
		FD_SET(csd, &readfds);

		tv.tv_sec = SERVICE_MODE_SELECT_TIMEOUT_MS/1000;
		tv.tv_usec = (SERVICE_MODE_SELECT_TIMEOUT_MS%1000)*1000;

		ret = select(csd+1, &readfds , NULL , NULL , &tv);
		errsv = errno;
		if ((ret < 0) && (errsv != EINTR)) {
			fprintf(stderr, "[-] Error on socket select: %d\n", errsv);
			break;
		}

		if(ret <= 0) /* Select timeout or EINTR */
			continue;

		cd = accept(csd, NULL, NULL);
		if (cd >= 0) {
			struct service_command_ctx svc_ctx = { .cd = cd };
			ret = read_command(cd, &svc_ctx.svc_cmd);
			if (ret < 0) {
				fprintf(stderr, "%s(): Error reading a command!\n", __func__);
				close(cd);
				continue;
			}

			service_command(&svc_ctx);
			continue;
		}

		errsv = errno;
		if (errsv != EAGAIN || errsv != EWOULDBLOCK) {
			fprintf(stdout, "[-] Error on socket accept: %d\n", errsv);
			break;
		}
	}

	service_cmds_interrupt();
	pthread_join(svc_cmd_thread_id, NULL);

err:

	close(csd);
	if (!listen_port)
		unlink(listen_location);

	cleanup_checkpointed_pids();

	return ret;
}

static int user_interactive_mode(pid_t pid)
{
	int ret;

	ret = seize_target(pid);
	if (ret)
		return ret;

	ret = execute_parasite_checkpoint(pid);
	if (ret)
		goto out;

	if (!no_wait && !interrupted) {
		long dms;
		long h, m, s, ms;
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);

		fprintf(stdout, "[x] --> press enter to restore process memory and unfreeze <--\n");
		fgetc(stdin);

		dms = diff_ms(&ts);
		h = dms/1000/60/60;
		m = (dms/1000/60) % 60;
		s = (dms/1000) % 60;
		ms = dms % 1000;
		fprintf(stdout, "[i] slept for %02lu:%02lu:%02lu.%03lu (%lu ms)\n", h, m, s, ms, dms);
	}

	ret = execute_parasite_restore(pid);

out:
	unseize_target();
	cleanup_pid(pid);

	return ret;
}

static void print_version(void)
{
	int ret;
	struct utsname utsn;
	char buf[256] = { 0 };

	ret = uname(&utsn);
	if (!ret)
		snprintf(buf, sizeof(buf), " kernel %s %s", utsn.release, utsn.machine);

	fprintf(stdout, "[i] memcr %s %s%s\n", GIT_VERSION, ARCH_NAME, buf);
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s [-h] [-p PID] [-d DIR] [-S DIR] [-l PORT|PATH] [-n] [-m] [-f] [-z] [-c] [-e] [-V]\n" \
		"options:\n" \
		"  -h --help		help\n" \
		"  -p --pid		target process pid\n" \
		"  -d --dir		dir where memory dump is stored (defaults to /tmp)\n" \
		"  -S --parasite-socket-dir	dir where socket to communicate with parasite is created\n" \
		"        (abstract socket will be used if no path specified)\n" \
		"  -N --parasite-socket-netns	use network namespace of parasite when connecting to socket\n" \
		"        (useful if parasite is running in a container with netns)\n" \
		"  -l --listen		work as a service waiting for requests on a socket\n" \
		"        -l PORT: TCP port number to listen for requests on\n" \
		"        -l PATH: filesystem path for UNIX domain socket file (will be created)\n" \
		"  -n --no-wait		no wait for key press\n" \
		"  -m --proc-mem		get pages from /proc/pid/mem\n" \
		"  -f --rss-file		include file mapped memory\n" \
		"  -z --compress		compress memory dump\n" \
		"  -c --checksum		enable md5 checksum for memory dump\n" \
		"  -e --encrypt		enable encryption of memory dump\n" \
		"  -t --timeout		timeout in seconds for checkpoint/restore execution in service mode\n" \
		"  -V --version		print version and exit\n",
		name);

	exit(status);
}

static void __attribute__((noreturn)) die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(1);
}

int main(int argc, char *argv[])
{
	int ret;
	int opt;
	int option_index;
	int pid = 0;
	char *listen_location = NULL;
	int encrypt = 0;
	char *encrypt_arg = NULL;

	struct option long_options[] = {
		{ "help",			0,	NULL,	'h'},
		{ "pid",			1,	NULL,	'p'},
		{ "dir",			1,	NULL,	'd'},
		{ "parasite-socket-dir",	1,	NULL,	'S'},
		{ "parasite-socket-netns",	0,	NULL,	'N'},
		{ "listen",			1,	NULL,	'l'},
		{ "no-wait",			0,	NULL,	'n'},
		{ "proc-mem",			0,	NULL,	'm'},
		{ "rss-file",			0,	NULL,	'f'},
		{ "compress",			0,	NULL,	'z'},
		{ "checksum",			0,	NULL,	'c'},
		{ "encrypt",			2,	0,	'e'},
		{ "timeout",			1,	0,	't'},
		{ "version",			0,	0,	'V'},
		{ NULL,				0,	NULL,	0  }
	};

	dump_dir = "/tmp";
	parasite_socket_dir = NULL;
	parasite_socket_use_netns = 0;

	while ((opt = getopt_long(argc, argv, "hp:d:S:Nl:nmfzce::t:V", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'd':
				dump_dir = optarg;
				break;
			case 'S':
				parasite_socket_dir = optarg;
				break;
			case 'N':
				parasite_socket_use_netns = 1;
				break;
			case 'l':
				listen_location = optarg;
				service = 1;
				break;
			case 'n':
				no_wait = 1;
				break;
			case 'm':
				proc_mem = 1;
				break;
			case 'f':
				rss_file = 1;
				break;
			case 'z':
#ifndef COMPRESS_LZ4
				die("compression not available, recompile with COMPRESS_LZ4=1\n");
#endif
				compress = 1;
				break;
			case 'c':
#ifndef CHECKSUM_MD5
				die("checksumming not available, recompile with CHECKSUM_MD5=1\n");
#endif
				checksum = 1;
				break;
			case 'e':
				encrypt = 1;
				if (optarg)
					encrypt_arg = optarg;
				else if (optind < argc && argv[optind][0] != '-')
					encrypt_arg = argv[optind++];
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'V':
				print_version();
				exit(0);
			default: /* '?' */
				usage(argv[0], 1);
		}
	}

	if (!pid && !listen_location)
		usage(argv[0], 1);

	if (pid <= 0 && !listen_location)
		die("pid must be > 0\n");

	print_version();

	page_size = getpagesize();

	ret = access("/proc/self/pagemap", F_OK);
	if (ret)
		die("/proc/self/pagemap not present (depends on CONFIG_PROC_PAGE_MONITOR)\n");

	ret = access("/proc/kpageflags", F_OK);
	if (ret)
		die("/proc/kpageflags not present (depends on CONFIG_PROC_PAGE_MONITOR)\n");

	register_signal_handlers();

	setvbuf(stdout, NULL, _IOLBF, 0);

	if (lib__init) {
		ret = lib__init(encrypt, encrypt_arg);
		if (ret)
			exit(1);
	} else if (encrypt)
		die("encryption not available, preload libencrypt.so\n");

	kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpageflags_fd == -1)
		die("/proc/kpageflags: %m\n");

	if (listen_location)
		ret = service_mode(listen_location);
	else
		ret = user_interactive_mode(pid);

	if (lib__fini)
		lib__fini();

	close(kpageflags_fd);

	return ret;
}

