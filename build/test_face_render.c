#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FT_Library lib; FT_Face face;
    if (FT_Init_FreeType(&lib)) return 1;
    if (FT_New_Face(lib, argv[1], 0, &face)) return 1;
    fprintf(stderr, "num_glyphs=%ld\n", face->num_glyphs);
    for (int px = 8; px <= 128; px += 4) {
        FT_Set_Pixel_Sizes(face, 0, px);
        for (long g = 0; g < face->num_glyphs; g++) {
            if (FT_Load_Glyph(face, g, FT_LOAD_DEFAULT) == 0)
                FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
        }
    }
    FT_Done_Face(face); FT_Done_FreeType(lib);
    return 0;
}
