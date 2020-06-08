#ifndef gw_body_data_H
#define gw_body_data_H

#include "body.h"

enum gw_body_type {GW_BT_NONE=0, GW_BT_FILE, GW_BT_MEM};

typedef struct gw_body_data {
    union {
        ci_simple_file_t *file;
        ci_membuf_t *mem;
    } store;
    int buf_exceed;
    ci_simple_file_t *decoded;
    enum gw_body_type type;
} gw_body_data_t;

#define gw_body_data_lock_all(bd) (void)((bd)->type == GW_BT_FILE && (ci_simple_file_lock_all((bd)->store.file)))
#define gw_body_data_unlock(bd, len) (void)((bd)->type == GW_BT_FILE && (ci_simple_file_unlock((bd)->store.file, len)))
#define gw_body_data_unlock_all(bd) (void)((bd)->type == GW_BT_FILE && (ci_simple_file_unlock_all((bd)->store.file)))
#define gw_body_data_size(bd) ((bd)->type == GW_BT_FILE ? (bd)->store.file->endpos : ((bd)->type == GW_BT_MEM ? (bd)->store.mem->endpos : 0))

void gw_body_data_new(gw_body_data_t *bd, enum gw_body_type type,  int size);
void gw_body_data_named(gw_body_data_t *bd, const char *dir, const char *name);
void gw_body_data_destroy(gw_body_data_t *body);
void gw_body_data_release(gw_body_data_t *body);
int gw_body_data_write(gw_body_data_t *body, char *buf, int len, int iseof);
int gw_body_data_read(gw_body_data_t *body, char *buf, int len);
void gw_body_data_replace_body(gw_body_data_t *body, char *buf, int len);

int gw_decompress_to_simple_file(int encodingMethod, const char *inbuf, size_t inlen, struct ci_simple_file *outfile, ci_off_t max_size);
#endif
