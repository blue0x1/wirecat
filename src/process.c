#include "process.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int make_pipe(int p[2])
{
    if (pipe(p) < 0) {
        return -1;
    }
    return 0;
}

int wcat_process_spawn(const char *path, int use_pty, wcat_process *proc)
{
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    pid_t pid;

    memset(proc, 0, sizeof(*proc));
    proc->pid = -1;
    proc->in_fd = -1;
    proc->out_fd = -1;
    proc->err_fd = -1;
    proc->pty_fd = -1;

    if (use_pty) {
        pid = forkpty(&proc->pty_fd, NULL, NULL, NULL);
        if (pid < 0) {
            return -1;
        }
        if (pid == 0) {
            execl(path, path, (char *)NULL);
            _exit(127);
        }
        proc->pid = pid;
        proc->in_fd = proc->pty_fd;
        proc->out_fd = proc->pty_fd;
        return 0;
    }

    if (make_pipe(in_pipe) < 0 || make_pipe(out_pipe) < 0) {
        goto fail;
    }
    pid = fork();
    if (pid < 0) {
        goto fail;
    }
    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(out_pipe[1], STDERR_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        execl(path, path, (char *)NULL);
        _exit(127);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    proc->pid = pid;
    proc->in_fd = in_pipe[1];
    proc->out_fd = out_pipe[0];
    return 0;

fail:
    (void)wcat_close_quiet(in_pipe[0]);
    (void)wcat_close_quiet(in_pipe[1]);
    (void)wcat_close_quiet(out_pipe[0]);
    (void)wcat_close_quiet(out_pipe[1]);
    return -1;
}

void wcat_process_close(wcat_process *proc)
{
    int in_fd;
    int out_fd;
    int err_fd;
    int pty_fd;

    if (proc == NULL) {
        return;
    }
    in_fd = proc->in_fd;
    out_fd = proc->out_fd;
    err_fd = proc->err_fd;
    pty_fd = proc->pty_fd;

    if (in_fd >= 0) {
        (void)wcat_close_quiet(in_fd);
    }
    if (out_fd >= 0 && out_fd != in_fd) {
        (void)wcat_close_quiet(out_fd);
    }
    if (err_fd >= 0 && err_fd != in_fd && err_fd != out_fd) {
        (void)wcat_close_quiet(err_fd);
    }
    if (pty_fd >= 0 && pty_fd != in_fd && pty_fd != out_fd && pty_fd != err_fd) {
        (void)wcat_close_quiet(pty_fd);
    }
    proc->in_fd = -1;
    proc->out_fd = -1;
    proc->err_fd = -1;
    proc->pty_fd = -1;
}

int wcat_process_wait(wcat_process *proc)
{
    int status = 0;

    if (proc == NULL || proc->pid <= 0) {
        return 0;
    }
    while (waitpid(proc->pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return status;
}
