#include <stdio.h>
#include <stdlib.h>

void init(void)   { volatile int w = 0; (void)w; }
void parse(void)  { volatile int w = 0; (void)w; }
void tick(void)   { volatile int w = 0; (void)w; }
void cleanup(void){ volatile int w = 0; (void)w; }

int main(int argc, char **argv)
{
    init();
    parse();
    FILE *f = fopen(argv[1], "r");
    int n = 0;
    if (f) { fscanf(f, "%d", &n); fclose(f); }
    for (int i = 0; i < 5; i++) {
        tick();
    }
    cleanup();
    return 0;
}
