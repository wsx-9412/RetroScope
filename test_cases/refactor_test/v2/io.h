#ifndef IO_H
#define IO_H

#include "data.h"

int read_input(const char *filename, DataSet *ds);
int write_output(const char *filename, DataSet *ds);
void log_message(const char *msg);

#endif
