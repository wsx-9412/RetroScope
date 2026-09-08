#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "data.h"

DataSet *create_dataset(size_t count) {
    DataSet *ds = (DataSet *)malloc(sizeof(DataSet));
    if (!ds) return NULL;
    ds->values = (int *)malloc(count * sizeof(int));
    if (!ds->values) {
        free(ds);
        return NULL;
    }
    ds->count = count;
    ds->min_val = 0;
    ds->max_val = 0;
    ds->avg = 0.0;
    return ds;
}

void destroy_dataset(DataSet *ds) {
    if (ds) {
        free(ds->values);
        free(ds);
    }
}

/* RENAMED: validate_input -> check_input */
int check_input(DataSet *ds) {
    if (!ds || !ds->values || ds->count == 0) {
        return -1;
    }
    for (size_t i = 0; i < ds->count; i++) {
        if (ds->values[i] < -1000 || ds->values[i] > 1000) {
            return -2;
        }
    }
    return 0;
}

/* SPLIT: filter_outliers extracted from handle_data */
void filter_outliers(DataSet *ds) {
    if (!ds || !ds->values) return;
    for (size_t i = 0; i < ds->count; i++) {
        if (ds->values[i] > 500) ds->values[i] = 500;
        if (ds->values[i] < -500) ds->values[i] = -500;
    }
}

/* RENAMED: process_data -> handle_data (now calls filter_outliers) */
void handle_data(DataSet *ds) {
    if (!ds || !ds->values) return;
    filter_outliers(ds);
    for (size_t i = 0; i < ds->count; i++) {
        ds->values[i] = ds->values[i] * 2 + 1;
    }
}

void compute_statistics(DataSet *ds) {
    if (!ds || !ds->values || ds->count == 0) return;
    ds->min_val = ds->values[0];
    ds->max_val = ds->values[0];
    long sum = 0;
    for (size_t i = 0; i < ds->count; i++) {
        if (ds->values[i] < ds->min_val) ds->min_val = ds->values[i];
        if (ds->values[i] > ds->max_val) ds->max_val = ds->values[i];
        sum += ds->values[i];
    }
    ds->avg = (double)sum / ds->count;
}

/* RENAMED: normalize_data -> rescale_data */
void rescale_data(DataSet *ds) {
    if (!ds || !ds->values || ds->count == 0) return;
    int range = ds->max_val - ds->min_val;
    if (range == 0) return;
    for (size_t i = 0; i < ds->count; i++) {
        ds->values[i] = (int)(((double)(ds->values[i] - ds->min_val) / range) * 100);
    }
}

void sort_data(DataSet *ds) {
    if (!ds || !ds->values || ds->count <= 1) return;
    for (size_t i = 0; i < ds->count - 1; i++) {
        for (size_t j = 0; j < ds->count - i - 1; j++) {
            if (ds->values[j] > ds->values[j + 1]) {
                int tmp = ds->values[j];
                ds->values[j] = ds->values[j + 1];
                ds->values[j + 1] = tmp;
            }
        }
    }
}

int find_peak(DataSet *ds) {
    if (!ds || !ds->values || ds->count == 0) return -1;
    int peak_idx = 0;
    for (size_t i = 1; i < ds->count; i++) {
        if (ds->values[i] > ds->values[peak_idx]) {
            peak_idx = (int)i;
        }
    }
    return peak_idx;
}

void smooth_data(DataSet *ds, int window) {
    if (!ds || !ds->values || ds->count == 0 || window <= 0) return;
    int *tmp = (int *)malloc(ds->count * sizeof(int));
    if (!tmp) return;
    memcpy(tmp, ds->values, ds->count * sizeof(int));
    for (size_t i = 0; i < ds->count; i++) {
        int sum = 0, cnt = 0;
        for (int j = -(window / 2); j <= window / 2; j++) {
            int idx = (int)i + j;
            if (idx >= 0 && idx < (int)ds->count) {
                sum += tmp[idx];
                cnt++;
            }
        }
        ds->values[i] = sum / cnt;
    }
    free(tmp);
}

void print_summary(DataSet *ds) {
    if (!ds) return;
    printf("DataSet: count=%zu min=%d max=%d avg=%.2f\n",
           ds->count, ds->min_val, ds->max_val, ds->avg);
}
