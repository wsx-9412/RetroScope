#ifndef DATA_H
#define DATA_H

#include <stddef.h>

typedef struct {
    int *values;
    size_t count;
    int min_val;
    int max_val;
    double avg;
} DataSet;

DataSet *create_dataset(size_t count);
void destroy_dataset(DataSet *ds);
int validate_input(DataSet *ds);
void process_data(DataSet *ds);
void compute_statistics(DataSet *ds);
void normalize_data(DataSet *ds);
void sort_data(DataSet *ds);
int find_peak(DataSet *ds);
void smooth_data(DataSet *ds, int window);
void print_summary(DataSet *ds);

#endif
