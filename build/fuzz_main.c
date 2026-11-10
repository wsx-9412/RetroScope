#include <stdio.h>
#include <stdlib.h>
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const char *data, size_t size);
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) return 1;
    fclose(f);
    LLVMFuzzerInitialize(&argc, &argv);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
