#ifndef WCAT_PROCESS_H
#define WCAT_PROCESS_H

#include <sys/types.h>

typedef struct {
    pid_t pid;
    int in_fd;
    int out_fd;
    int err_fd;
    int pty_fd;
} wcat_process;

int wcat_process_spawn(const char *path, int use_pty, wcat_process *proc);
void wcat_process_close(wcat_process *proc);
int wcat_process_wait(wcat_process *proc);

#endif

