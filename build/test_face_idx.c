#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FT_Library lib; FT_Face face;
    FT_Init_FreeType(&lib);
    FT_New_Face(lib, argv[1], -4939615758108852224LL, &face);
    FT_Done_FreeType(lib);
    return 0;
}
