#include "signalx.h"

#include <string.h>

volatile sig_atomic_t wcat_stop;

static void on_signal(int signo)
{
    (void)signo;
    wcat_stop = 1;
}

int wcat_signal_setup(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        return -1;
    }
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

