#include <stdio.h>
#include <stdlib.h>

void init(void)   { volatile int w = 0; (void)w; }
void parse(void)  { volatile int w = 0; (void)w; }
void do_a(void)   { volatile int w = 0; (void)w; }
void do_b(void)   { volatile int w = 0; (void)w; }
void cleanup(void){ volatile int w = 0; (void)w; }

int main(int argc, char **argv)
{
    init();
    parse();
    FILE *f = fopen(argv[1], "r");
    int x = 0;
    if (f) { fscanf(f, "%d", &x); fclose(f); }
    if (x > 20) {
        do_a();
    } else {
        do_b();
    }
    cleanup();
    return 0;
}
