#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FT_Library lib; FT_Face face;
    if (FT_Init_FreeType(&lib)) return 1;
    if (FT_New_Face(lib, argv[1], 0, &face)) { fprintf(stderr,"open fail\n"); return 1; }
    FT_MM_Var *mm = NULL;
    if (FT_Get_MM_Var(face, &mm) == 0 && mm) {
        fprintf(stderr, "axes=%u\n", mm->num_axis);
        if (mm->num_axis > 0) {
            FT_Fixed *coords = malloc(sizeof(FT_Fixed)*mm->num_axis);
            for (unsigned i = 0; i < mm->num_axis; i++) coords[i] = mm->axis[i].def;
            FT_Set_Var_Design_Coordinates(face, mm->num_axis, coords);
            free(coords);
        }
    }
    FT_Set_Pixel_Sizes(face, 0, 48);
    for (long g = 0; g < face->num_glyphs && g < 300; g++)
        FT_Load_Glyph(face, g, FT_LOAD_DEFAULT);
    FT_Done_Face(face); FT_Done_FreeType(lib);
    return 0;
}
