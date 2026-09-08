#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "data.h"

DataSet *create_dataset(size_t n) {
    DataSet *ds = malloc(sizeof(DataSet));
    ds->values = malloc(n * sizeof(int));
    ds->count = n;
    return ds;
}

void destroy_dataset(DataSet *ds) {
    if (ds) { free(ds->values); free(ds); }
}

void compute_statistics(DataSet *ds) {
    long sum = 0;
    for (size_t i = 0; i < ds->count; i++) sum += ds->values[i];
    printf("avg=%.2f\n", (double)sum / ds->count);
}

void sort_data(DataSet *ds) {
    for (size_t i = 0; i < ds->count - 1; i++)
        for (size_t j = 0; j < ds->count - i - 1; j++)
            if (ds->values[j] > ds->values[j+1]) {
                int t = ds->values[j]; ds->values[j] = ds->values[j+1]; ds->values[j+1] = t;
            }
}

void print_summary(DataSet *ds) {
    printf("count=%zu\n", ds->count);
}

/* V5: THREE separate functions */
int validate_input(DataSet *ds) {
    for (size_t i = 0; i < ds->count; i++)
        if (ds->values[i] < -999 || ds->values[i] > 999)
            return -1;
    return 0;
}

void process_buffer(DataSet *ds) {
    for (size_t i = 0; i < ds->count; i++)
        ds->values[i] = ds->values[i] * 3 + 7;
}

void log_operation(DataSet *ds) {
    printf("processed %zu items\n", ds->count);
}

int main(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]); return 1; }
    DataSet *ds = create_dataset(128);
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("open"); return 1; }
    fread(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);

    compute_statistics(ds);

    /* three separate functions called in sequence */
    if (validate_input(ds) == 0) {
        process_buffer(ds);
        log_operation(ds);
    }

    sort_data(ds);
    compute_statistics(ds);
    print_summary(ds);

    fp = fopen(argv[2], "wb");
    fwrite(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);
    destroy_dataset(ds);
    return 0;
}
