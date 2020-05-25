#include <wchar.h>
#include "body.h"
#include "simple_api.h"
#include "c-icap.h"
#include "service.h"
#include "request.h"
#include "gwfile.h"
#include "debug.h"
#include <locale.h>
#include <stdlib.h>

#define BUFFER_SIZE 50

int gw_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);
int gw_post_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf);
void gw_close_service();
void *gw_init_request_data(struct ci_request *req);
void gw_release_request_data(void *srv_data);
int gw_check_preview_handler(char *preview_data, int preview_data_len, struct ci_request *req);
int gw_end_of_data_handler(struct ci_request *req);
int gw_service_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, struct ci_request *req);


CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "gw_test",                    /* mod_name, The module name */
    "Glasswall Test service",     /* mod_short_descr,  Module short description */
    ICAP_RESPMOD | ICAP_REQMOD,   /* mod_type, The service type is responce or request modification */
    gw_init_service,              /* mod_init_service. Service initialization */
    NULL,				          /* post_init_service. Service initialization after c-icap configured. Not used here */
    gw_close_service,             /* mod_close_service. Called when service shutdowns. */
    gw_init_request_data,         /* mod_init_request_data */
    gw_release_request_data,      /* mod_release_request_data */
    gw_check_preview_handler,     /* mod_check_preview_handler */
    gw_end_of_data_handler,       /* mod_end_of_data_handler */
    gw_service_io,                        /* mod_service_io */
    NULL,
    NULL
};

struct gw_test_req_data {
    /*the body data*/
    ci_ring_buf_t *body;
    /*flag for marking the eof*/
    int eof;
};

int gw_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf)
{
	setlocale(LC_ALL, "");
    ci_debug_printf(5, "gw_init_service......\n");
	// Load the Glasswall library and get the version
	wchar_t* wsdkVersion = GWFileVersion();
	char* sdkVersion = (char *)malloc(BUFFER_SIZE);
	wcstombs(sdkVersion, wsdkVersion, 20);
		
	ci_debug_printf(4, "Glasswall SDK Version = %s\n", sdkVersion); 
	
	/*Tell to the icap clients that we can support up to 1024 size of preview data*/
    ci_service_set_preview(srv_xdata, 1024);

    /*Tell to the icap clients that we support 204 responses*/
    ci_service_enable_204(srv_xdata);

    /*Tell to the icap clients to send preview data for all files*/
    ci_service_set_transfer_preview(srv_xdata, "*");
	
    return CI_OK;
}

void gw_close_service()
{
    ci_debug_printf(5, "gw_close_service......\n");
}

void *gw_init_request_data(struct ci_request *req)
{
    ci_debug_printf(5, "gw_init_request_data......\n");
	
	struct gw_test_req_data *gw_test_data;

    /*Allocate memory fot the gw_test_data*/
    gw_test_data = malloc(sizeof(struct gw_test_req_data));
    if (!gw_test_data) {
        ci_debug_printf(1, "Memory allocation failed inside gw_init_request_data!\n");
        return NULL;
    }

    /*If the ICAP request encuspulates a HTTP objects which contains body data
      and not only headers allocate a ci_cached_file_t object to store the body data.
     */
    if (ci_req_hasbody(req))
        gw_test_data->body = ci_ring_buf_new(4096);
    else
        gw_test_data->body = NULL;

    gw_test_data->eof = 0;
    /*Return to the c-icap server the allocated data*/
    return gw_test_data;
}

void gw_release_request_data(void *srv_data)
{
    ci_debug_printf(5, "gw_release_request_data......\n");
	struct gw_test_req_data *gw_test_data = (struct gw_test_req_data *)srv_data;
	
	    /*if we had body data, release the related allocated data*/
    if (gw_test_data->body)
        ci_ring_buf_destroy(gw_test_data->body);

    free(gw_test_data);
}

int gw_check_preview_handler(char *preview_data, int preview_data_len, struct ci_request *req)
{
    ci_debug_printf(5, "gw_check_preview_handler......\n");
	
	ci_off_t content_len;
	
	struct gw_test_req_data *gw_test_data = ci_service_data(req);
	
	content_len = ci_http_content_length(req);
    ci_debug_printf(9, "We expect to read :%" PRINTF_OFF_T " body data\n",
                    (CAST_OFF_T) content_len);
	
	if (!ci_req_hasbody(req)){
		ci_debug_printf(6, "No body data, allow 204\n");
		return CI_MOD_ALLOW204;
    }
	
	/*Unlock the request body data so the c-icap server can send data before
      all body data has received */
	ci_req_unlock_data(req);
	
	/*If there are not preview data tell to the client to continue sending data
      (http object modification required). */
    if (!preview_data_len)
        return CI_MOD_CONTINUE;
	
	ci_debug_printf(8, "Gw_Test service will process the request\n");
	
	 /*if we have preview data and we want to proceed with the request processing
          we should store the preview data. */
	if (preview_data_len) {
		ci_ring_buf_write(gw_test_data->body, preview_data, preview_data_len);
		gw_test_data->eof = ci_req_hasalldata(req);
	}
	return CI_MOD_CONTINUE;
}

static int rebuild(ci_request_t *req, struct gw_test_req_data *data);
int gw_end_of_data_handler(struct ci_request *req)
{
    ci_debug_printf(5, "gw_end_of_data_handler......\n");
	struct gw_test_req_data *gw_test_data = ci_service_data(req);
	
    /*mark the eof*/
    gw_test_data->eof = 1;
	
	if (rebuild(req, gw_test_data) == CI_ERROR) {
        ci_debug_printf(1, "Error while rebuilding document. Aborting....\n");
        return CI_ERROR;
    }
	 
    return CI_MOD_DONE;
}

int gw_service_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, struct ci_request *req)
{
    ci_debug_printf(5, "gw_service_io......\n");
    int ret;
    struct gw_test_req_data *gw_test_data = ci_service_data(req);
    ret = CI_OK;

    /*write the data read from icap_client to the echo_data->body*/
    if (rlen && rbuf) {
        *rlen = ci_ring_buf_write(gw_test_data->body, rbuf, *rlen);
		if (*rlen == CI_ERROR)
	       return CI_ERROR;
    }

    /*read some data from the gw_test_data->body and put them to the write buffer to be send
     to the ICAP client*/
    if (wbuf && wlen) {
        *wlen = ci_ring_buf_read(gw_test_data->body, wbuf, *wlen);
        if (*wlen == 0 && gw_test_data->eof == 1)
            *wlen = CI_EOF;
    }

    return ret;
}

static int rebuild(ci_request_t *req, struct gw_test_req_data *data)
{

	return CI_OK;
}