#include "gw_body.h"
#include "c_icap/simple_api.h"
#include "../../common.h"
#include <assert.h>

void gw_body_data_new(gw_body_data_t *bd, enum gw_body_type type, int size)
{
    if (type == GW_BT_FILE) {
        bd->store.file = ci_simple_file_new(size);
        if (bd->store.file)
            bd->type = type;
    }
    else if (type == GW_BT_MEM) {
        bd->store.mem = ci_membuf_new_sized(size);
        if (bd->store.mem)
            bd->type = type;
    }
    else
        bd->type = GW_BT_NONE;
    bd->buf_exceed = 0;
    bd->decoded = NULL;
}

void gw_body_data_named(gw_body_data_t *bd, const char *dir, const char *name)
{
    bd->store.file = ci_simple_file_named_new((char *)dir, (char *)name, 0);
    if (bd->store.file)
        bd->type = GW_BT_FILE;
    else
        bd->type = GW_BT_NONE;

    bd->buf_exceed = 0;
}

void gw_body_data_destroy(gw_body_data_t *body)
{
    if (body->type == GW_BT_NONE)
        return; /*Nothing to do*/
    if (body->type == GW_BT_FILE) {
        ci_simple_file_destroy(body->store.file);
        body->store.file = NULL;
        body->type = GW_BT_NONE;
    }
    else if (body->type == GW_BT_MEM) {
        ci_membuf_free(body->store.mem);
        body->store.mem = NULL;
        body->type = GW_BT_NONE;
    }
    if (body->decoded) {
        ci_simple_file_destroy(body->decoded);
        body->decoded = NULL;
    }
}

void gw_body_data_release(gw_body_data_t *body)
{
    /*This is make sense only for ci_simple_file_t objects.
      Means that the file will be closed but not removed from disk
      It is used only in vir_mode.
     */
    assert(body->type == GW_BT_FILE);
    ci_simple_file_release(body->store.file);
    body->store.file = NULL;
    body->type = GW_BT_NONE;
    if (body->decoded) {
        ci_simple_file_destroy(body->decoded);
        body->decoded = NULL;
    }
}

int gw_body_data_write(gw_body_data_t *body, char *buf, int len, int iseof)
{
    int memsize;
    if (body->type == GW_BT_FILE)
        return ci_simple_file_write(body->store.file, buf, len, iseof);
    else if (body->type == GW_BT_MEM) {
        if (body->buf_exceed)
            return 0; /*or just consume everything?*/
        memsize = body->store.mem->bufsize - body->store.mem->endpos;
        if (memsize < len) {
            body->buf_exceed = 1;
            return 0;
        }
        return ci_membuf_write(body->store.mem, buf, len, iseof);
    }
    return 0;
}

int gw_body_data_read(gw_body_data_t *body, char *buf, int len)
{
    if (body->type == GW_BT_FILE)
        return ci_simple_file_read(body->store.file, buf, len);
    else if (body->type == GW_BT_MEM)
        return ci_membuf_read(body->store.mem, buf, len);
    return 0;
}

void gw_body_data_replace_body(gw_body_data_t *body, char *buf, int len)
{
	int bt;
	bt = body->type;
	gw_body_data_destroy(body);
	gw_body_data_new(body, bt, len);
	gw_body_data_write(body, buf, len, 1);	
}

int gw_decompress_to_simple_file(int encodeMethod, const char *inbuf, size_t inlen, struct ci_simple_file *outfile, ci_off_t max_size)
{
#if defined(HAVE_CICAP_DECOMPRESS_TO)
    return ci_decompress_to_simple_file(encodeMethod, inbuf, inlen, outfile, max_size);
#else
    if (encodeMethod == CI_ENCODE_GZIP || encodeMethod == CI_ENCODE_DEFLATE)
        return ci_inflate_to_simple_file(inbuf, inlen, outfile, max_size);
    else if (encodeMethod == CI_ENCODE_BZIP2)
        return ci_bzunzip_to_simple_file(inbuf, inlen, outfile, max_size);
#if defined(HAVE_CICAP_BROTLI)
    else if (encodeMethod == CI_ENCODE_BROTLI)
        return ci_brinflate_to_simple_file(inbuf, inlen, outfile, max_size);
#endif
#endif
    return CI_UNCOMP_ERR_ERROR;
}
