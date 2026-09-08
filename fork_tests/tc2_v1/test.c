#include <stdio.h>
#include <stdlib.h>

void init(void)   { volatile int w = 0; (void)w; }
void parse(void)  { volatile int w = 0; (void)w; }
void proceed(void){ volatile int w = 0; (void)w; }
void fail(void)   { volatile int w = 0; (void)w; }
void cleanup(void){ volatile int w = 0; (void)w; }

void worker(int n)
{
    if (n > 5) {
        proceed();
    } else {
        fail();
    }
}

int main(int argc, char **argv)
{
    init();
    parse();
    FILE *f = fopen(argv[1], "r");
    int n = 0;
    if (f) { fscanf(f, "%d", &n); fclose(f); }
    worker(n);
    cleanup();
    return 0;
}
