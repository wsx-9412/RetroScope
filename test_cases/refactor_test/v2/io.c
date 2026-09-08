#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io.h"

/* RENAMED: read_input -> load_input */
int load_input(const char *filename, DataSet *ds) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        fclose(fp);
        return -2;
    }
    ds->count = size / sizeof(int);
    ds->values = (int *)realloc(ds->values, ds->count * sizeof(int));
    if (!ds->values) {
        fclose(fp);
        return -3;
    }
    size_t read_count = fread(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);
    if (read_count != ds->count) return -4;
    return 0;
}

/* RENAMED: write_output -> save_output */
int save_output(const char *filename, DataSet *ds) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    size_t written = fwrite(ds->values, sizeof(int), ds->count, fp);
    fclose(fp);
    return (written == ds->count) ? 0 : -1;
}

void log_message(const char *msg) {
    fprintf(stderr, "[LOG] %s\n", msg);
}
