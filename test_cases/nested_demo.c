/*
 * nested_demo.c - test program where the same function `helper` is called at
 * different call depths, to exercise lcs_trace.py's hierarchy-aware matching.
 *
 * input "A" -> processA(); helper();       (helper at depth 2, then depth 1)
 * input "B" -> helper(); processA();       (helper at depth 1, then depth 2)
 */
#include <stdio.h>
#include <string.h>
#define W() do { volatile int w = 0; (void)w; } while (0)

void helper(void)   { W(); }
void processA(void) { helper(); }   /* helper at depth 2 */

int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "r");
    if (!f) return 1;
    char buf[64] = {0};
    fgets(buf, sizeof buf, f);
    if (strncmp(buf, "A", 1) == 0) {
        processA();   /* -> helper at depth 2 */
        helper();     /* -> helper at depth 1 */
    } else {
        helper();     /* -> helper at depth 1 */
        processA();   /* -> helper at depth 2 */
    }
    fclose(f);
    return 0;
}
