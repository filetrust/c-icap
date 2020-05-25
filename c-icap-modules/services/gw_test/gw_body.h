#ifndef gw_body_data_H
#define gw_body_data_H

#include "body.h"

enum av_body_type {AV_BT_NONE=0, AV_BT_FILE, AV_BT_MEM};

struct gw_body_data {
    union {
        ci_simple_file_t *file;
        ci_membuf_t *mem;
    } store;
    int buf_exceed;
    ci_simple_file_t *decoded;
    enum av_body_type type;
};

#define gw_body_data_lock_all(bd) (void)((bd)->type == AV_BT_FILE && (ci_simple_file_lock_all((bd)->store.file)))
#define gw_body_data_unlock(bd, len) (void)((bd)->type == AV_BT_FILE && (ci_simple_file_unlock((bd)->store.file, len)))
#define gw_body_data_unlock_all(bd) (void)((bd)->type == AV_BT_FILE && (ci_simple_file_unlock_all((bd)->store.file)))
#define gw_body_data_size(bd) ((bd)->type == AV_BT_FILE ? (bd)->store.file->endpos : ((bd)->type == AV_BT_MEM ? (bd)->store.mem->endpos : 0))

void gw_body_data_new(struct gw_body_data *bd, enum av_body_type type,  int size);
void gw_body_data_named(struct gw_body_data *bd, const char *dir, const char *name);
void gw_body_data_destroy(struct gw_body_data *body);
void gw_body_data_release(struct gw_body_data *body);
int gw_body_data_write(struct gw_body_data *body, char *buf, int len, int iseof);
int gw_body_data_read(struct gw_body_data *body, char *buf, int len);

int gw_decompress_to_simple_file(int encodingMethod, const char *inbuf, size_t inlen, struct ci_simple_file *outfile, ci_off_t max_size);
#endif
