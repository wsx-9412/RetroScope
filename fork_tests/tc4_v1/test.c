#include <stdio.h>
#include <stdlib.h>

void init(void)  { volatile int w = 0; (void)w; }
void parse(void) { volatile int w = 0; (void)w; }
void a(void)     { volatile int w = 0; (void)w; }
void b(void)     { volatile int w = 0; (void)w; }
void c(void)     { volatile int w = 0; (void)w; }
void done(void)  { volatile int w = 0; (void)w; }

int main(int argc, char **argv)
{
    init();
    parse();
    FILE *f = fopen(argv[1], "r");
    int mode = 0;
    if (f) { fscanf(f, "%d", &mode); fclose(f); }
    if (mode == 1) {
        a();
    } else if (mode == 2) {
        b();
    } else {
        c();
    }
    done();
    return 0;
}
