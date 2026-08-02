#ifndef WCAT_FILEXFER_H
#define WCAT_FILEXFER_H

#include "cli.h"

int wcat_send_file(const wcat_config *cfg);
int wcat_recv_file(const wcat_config *cfg);

#endif

