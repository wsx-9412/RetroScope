#ifndef DATA_H
#define DATA_H
#include <stddef.h>
typedef struct { int *values; size_t count; } DataSet;
DataSet *create_dataset(size_t n);
void destroy_dataset(DataSet *ds);
void compute_statistics(DataSet *ds);
void sort_data(DataSet *ds);
void validate_and_process(DataSet *ds);
void print_summary(DataSet *ds);
#endif
