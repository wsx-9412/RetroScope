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

/*
 * V3: ONE function does both validation AND processing.
 * V4: This function is SPLIT into validate_input + process_buffer.
 */
void validate_and_process(DataSet *ds) {
    /* --- validate --- */
    int invalid = 0;
    for (size_t i = 0; i < ds->count; i++) {
        if (ds->values[i] < -999 || ds->values[i] > 999) {
            invalid = 1;
            break;
        }
    }
    if (invalid) {
        printf("invalid data\n");
        return;
    }
    /* --- process --- */
    for (size_t i = 0; i < ds->count; i++) {
        ds->values[i] = ds->values[i] * 3 + 7;
    }
    printf("processed %zu items\n", ds->count);
}

int main(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]); return 1; }

    DataSet *ds = create_dataset(128);

    /* read binary input */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("open"); return 1; }
    fread(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);

    /* analyze: shared function — anchor for merge/split detection */
    compute_statistics(ds);

    /* the refactored function */
    validate_and_process(ds);

    /* more shared functions — anchors */
    sort_data(ds);
    compute_statistics(ds);
    print_summary(ds);

    /* write output */
    fp = fopen(argv[2], "wb");
    fwrite(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);

    destroy_dataset(ds);
    return 0;
}
