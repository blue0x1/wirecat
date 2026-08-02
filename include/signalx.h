#ifndef WCAT_SIGNALX_H
#define WCAT_SIGNALX_H

#include <signal.h>

extern volatile sig_atomic_t wcat_stop;

int wcat_signal_setup(void);

#endif

