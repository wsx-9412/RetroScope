/*
 * Dump FT_Get_Var_Design_Coordinates results for counts greater than the
 * number of axes.  FreeType's public docs say excess values should be zero.
 */
#include <errno.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path, size_t *len_out) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) || ftell(fp) < 0) {
    fclose(fp);
    return NULL;
  }
  long len = ftell(fp);
  rewind(fp);
  unsigned char *buf = malloc((size_t)len);
  if (!buf) {
    fclose(fp);
    return NULL;
  }
  if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
    free(buf);
    fclose(fp);
    return NULL;
  }
  fclose(fp);
  *len_out = (size_t)len;
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s FONT count\n", argv[0]);
    return 2;
  }
  const char *path = argv[1];
  unsigned count = (unsigned)strtoul(argv[2], NULL, 0);
  if (count > 256)
    count = 256;

  size_t len = 0;
  unsigned char *font = read_file(path, &len);
  if (!font)
    return 2;

  FT_Library lib = NULL;
  FT_Face face = NULL;
  FT_Error err = FT_Init_FreeType(&lib);
  if (err)
    return 1;
  err = FT_New_Memory_Face(lib, font, (FT_Long)len, 0, &face);
  fprintf(stderr, "FT_New_Memory_Face err=%d face=%p\n", err, (void *)face);
  if (err || !face)
    return 1;

  FT_MM_Var *mm = NULL;
  err = FT_Get_MM_Var(face, &mm);
  fprintf(stderr, "FT_Get_MM_Var err=%d mm=%p axes=%u namedstyles=%u\n", err,
          (void *)mm, mm ? mm->num_axis : 0, mm ? mm->num_namedstyles : 0);
  if (mm)
    FT_Done_MM_Var(lib, mm);

  FT_Fixed *coords = calloc(count ? count : 1, sizeof(*coords));
  if (!coords)
    return 1;
  err = FT_Get_Var_Design_Coordinates(face, count, coords);
  fprintf(stderr, "FT_Get_Var_Design_Coordinates count=%u err=%d\n", count,
          err);
  for (unsigned i = 0; i < count; i++) {
    printf("%03u 0x%08x %ld\n", i, (unsigned)(uint32_t)coords[i],
           (long)coords[i]);
  }

  if (getenv("PRINT_MAPS")) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
      char line[512];
      fprintf(stderr, "--- /proc/self/maps ---\n");
      while (fgets(line, sizeof(line), maps))
        fputs(line, stderr);
      fclose(maps);
      fprintf(stderr, "--- end maps ---\n");
    }
  }

  free(coords);
  FT_Done_Face(face);
  FT_Done_FreeType(lib);
  free(font);
  return err ? 1 : 0;
}
