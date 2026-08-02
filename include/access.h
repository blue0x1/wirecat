#ifndef WCAT_ACCESS_H
#define WCAT_ACCESS_H

#include "cli.h"

int wcat_access_validate_list(const char *list);
int wcat_access_check_fd(const wcat_config *cfg, int fd);

#endif
