#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FT_Library lib; FT_Face face;
    if (FT_Init_FreeType(&lib)) return 1;
    if (FT_New_Face(lib, argv[1], 0, &face)) { fprintf(stderr,"open fail\n"); return 1; }
    FT_Set_Pixel_Sizes(face, 0, 64);
    long n = face->num_glyphs;
    for (long g = 0; g < n && g < 100000; g++)
        FT_Load_Glyph(face, g, FT_LOAD_DEFAULT);
    FT_Done_Face(face); FT_Done_FreeType(lib);
    return 0;
}
