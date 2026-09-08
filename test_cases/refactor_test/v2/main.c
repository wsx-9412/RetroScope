#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "data.h"
#include "io.h"

/* RENAMED: analyze -> evaluate */
void evaluate(DataSet *ds) {
    log_message("Starting analysis...");
    compute_statistics(ds);
    print_summary(ds);
    int peak = find_peak(ds);
    printf("Peak index: %d\n", peak);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    DataSet *ds = create_dataset(256);
    if (!ds) {
        fprintf(stderr, "Failed to create dataset\n");
        return 1;
    }

    log_message("Reading input...");
    if (load_input(argv[1], ds) != 0) {
        fprintf(stderr, "Failed to read input\n");
        destroy_dataset(ds);
        return 1;
    }

    log_message("Validating input...");
    int rc = check_input(ds);
    if (rc != 0) {
        fprintf(stderr, "Validation failed: %d\n", rc);
        destroy_dataset(ds);
        return 1;
    }

    log_message("Analyzing data...");
    evaluate(ds);

    log_message("Processing data...");
    handle_data(ds);

    log_message("Computing statistics...");
    compute_statistics(ds);

    log_message("Normalizing...");
    rescale_data(ds);

    log_message("Sorting...");
    sort_data(ds);

    log_message("Smoothing...");
    smooth_data(ds, 3);

    log_message("Re-analyzing after processing...");
    evaluate(ds);

    log_message("Writing output...");
    if (save_output(argv[2], ds) != 0) {
        fprintf(stderr, "Failed to write output\n");
        destroy_dataset(ds);
        return 1;
    }

    log_message("Done.");
    destroy_dataset(ds);
    return 0;
}
