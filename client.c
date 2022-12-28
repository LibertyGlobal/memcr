#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>

#include "memcr.h"


static int xconnect()
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
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/memcrservice");

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

static int send_cmd(struct service_command cmd, struct service_response *resp)
{
    int cd;
    int ret;

    cd = xconnect();
    if (cd < 0)
        return cd;


    ret = write(cd, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd)) {
        fprintf(stderr, "%s() write cmd failed: ret %d, errno %m\n", __func__, ret);
        return -1;
    }

    ret = read(cd, resp, sizeof(struct service_response));

    close(cd);

    return ret;
}

static void usage(const char *name, int status)
{
    fprintf(status ? stderr : stdout,
        "%s -p PID [-c -r -e]\n" \
        "options: \n" \
        "  -h --help\t\thelp\n" \
        "  -p --pid\t\tprocess ID to be checkpointed / restored\n" \
        "  -c --checkpoint\tsend checkpoint command to memcr service\n" \
        "  -r --restore\t\tsend restore command to memcr service\n" \
        "  -e --exit\t\tstop the memcr service\n",
        name);
    exit(status);
}

int main(int argc, char *argv[])
{
    int opt;
    int checkpoint = 0;
    int restore = 0;
    int bye = 0;
    int option_index;
    struct service_command cmd = {0};
    struct service_response resp = {0};
    int pid = 0;

    static struct option long_options[] = {
        { "help",       0,  0,  0},
        { "pid",        1,  0,  0},
        { "checkpoint", 0,  0,  0},
        { "restore",    0,  0,  0},
        { "exit",       0,  0,  0},
        { NULL,         0,  0,  0}
    };

    while ((opt = getopt_long(argc, argv, "hp:cre", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0], 0);
                break;
            case 'p':
                pid = atoi(optarg);
                break;
            case 'c':
                checkpoint = 1;
                break;
            case 'r':
                restore = 1;
                break;
            case 'e':
                bye = 1;
                break;
            default: /* '?' */
                usage(argv[0], 1);
                break;
        }
    }

    if (!pid && (checkpoint || restore)) {
        fprintf(stderr, "no PID provided!\n");
        usage(argv[0], 1);
        return 0;
    }

    if (checkpoint && pid)
    {
        fprintf(stdout, "Will checkpoint %d.\n", pid);
        cmd.cmd = MEMCR_CHECKPOINT;
        cmd.pid = pid;
        send_cmd(cmd, &resp);
    }

    if (restore && pid)
    {
        fprintf(stdout, "Will restore %d.\n", pid);
        cmd.cmd = MEMCR_RESTORE;
        cmd.pid = pid;
        send_cmd(cmd, &resp);
    }

    if (bye)
    {
        fprintf(stdout, "Will close memcr.\n");
        cmd.cmd = MEMCR_EXIT;
        cmd.pid = 0;
        send_cmd(cmd, &resp);
    }


    fprintf(stdout, "Cmd executed, exiting.\n");fflush(stdout);

    return resp.resp_code;

}

