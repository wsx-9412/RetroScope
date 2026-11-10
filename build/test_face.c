#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <font>\n", argv[0]);
        return 1;
    }
    FT_Library library;
    FT_Face face;
    if (FT_Init_FreeType(&library)) return 1;
    if (FT_New_Face(library, argv[1], 0, &face)) {
        fprintf(stderr, "FT_New_Face failed\n");
        return 1;
    }
    if (FT_HAS_FIXED_SIZES(face)) {
        for (int i = 0; i < face->num_fixed_sizes; i++)
            fprintf(stderr, "strike %d: %dx%d\n", i,
                    face->available_sizes[i].width, face->available_sizes[i].height);
    }
    for (int px = 8; px <= 256; px += 2) {
        if (FT_Set_Pixel_Sizes(face, 0, px)) continue;
        FT_UInt gi = 0;
        FT_ULong c = FT_Get_First_Char(face, &gi);
        while (gi != 0) {
            FT_Error e = FT_Load_Glyph(face, gi, FT_LOAD_COLOR | FT_LOAD_DEFAULT);
            if (e) fprintf(stderr, "load err %d px %d gid %u\n", e, px, gi);
            c = FT_Get_Next_Char(face, c, &gi);
        }
    }
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
