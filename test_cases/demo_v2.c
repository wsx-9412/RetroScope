/*
 * demo_v2.c - version 2 of a demo parser used to test lcs_trace.py mode 2
 * (two different versions, same input, different traces).
 *
 * Differences vs demo_v1.c:
 *   - process_audio_a  -> process_audio_pcm   (renamed)
 *   - process_meta     -> process_metadata    (renamed)
 *   - new process_gapless step inserted in the audio path
 *   - app_validate split into app_validate + app_verify
 *
 * Build: gcc -O0 -g -finstrument-functions -o demo_v2 demo_v2.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORK() do { volatile int w = 0; (void)w; } while (0)

void app_start(void)    { WORK(); }
void app_open(void)     { WORK(); }
void app_read(void)     { WORK(); }
void app_parse(void)    { WORK(); }

void process_headers(void)   { WORK(); }
void process_audio_pcm(void) { WORK(); }   /* renamed from process_audio_a */
void process_audio_b(void)   { WORK(); }
void process_audio_c(void)   { WORK(); }
void process_video_a(void)   { WORK(); }
void process_video_b(void)   { WORK(); }
void process_gapless(void)   { WORK(); }   /* new in v2 */
void process_metadata(void)  { WORK(); }   /* renamed from process_meta */
void process_checksum(void)  { WORK(); }

void app_validate(void) { WORK(); }
void app_verify(void)   { WORK(); }        /* new in v2 (split from app_validate) */
void app_encode(void)   { WORK(); }
void app_write(void)    { WORK(); }
void app_close(void)    { WORK(); }
void app_finish(void)   { WORK(); }

void handle_error(void) { WORK(); }

int main(int argc, char **argv)
{
    app_start();

    if (argc < 2) { handle_error(); app_finish(); return 1; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { handle_error(); app_finish(); return 1; }

    app_open();
    char buf[256] = {0};
    app_read();
    if (fgets(buf, sizeof buf, f) == NULL) {
        handle_error(); app_close(); app_finish(); return 1;
    }
    app_parse();

    char kind[32] = {0};
    int mode = 0;
    if (sscanf(buf, "%31s %d", kind, &mode) < 1) {
        handle_error(); app_close(); app_finish(); return 1;
    }

    process_headers();

    if (strcmp(kind, "audio") == 0) {
        process_audio_pcm();
        if (mode == 1) {
            process_audio_b(); process_gapless(); process_checksum();
        } else if (mode == 2) {
            process_audio_c(); process_audio_b();
        } else {
            process_audio_b();
        }
        process_metadata();
    } else if (strcmp(kind, "video") == 0) {
        process_video_a();
        process_video_b();
        if (mode >= 2) process_checksum();
        process_metadata();
    } else {
        handle_error(); app_close(); app_finish(); return 1;
    }

    app_validate();
    app_verify();
    app_encode();
    app_write();
    app_close();
    fclose(f);
    app_finish();
    return 0;
}
