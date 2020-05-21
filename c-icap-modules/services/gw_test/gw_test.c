#include "c-icap.h"
#include "service.h"
#include "request.h"

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
    gw_post_init_service,         /* post_init_service. Service initialization after c-icap configured. Not used here */
    gw_close_service,             /* mod_close_service. Called when service shutdowns. */
    gw_init_request_data,         /* mod_init_request_data */
    gw_release_request_data,      /* mod_release_request_data */
    gw_check_preview_handler,     /* mod_check_preview_handler */
    gw_end_of_data_handler,       /* mod_end_of_data_handler */
    gw_service_io,                        /* mod_service_io */
    NULL,
    NULL
};

int gw_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "gw_init_service......\n");
    return CI_OK;
}

int gw_post_init_service(ci_service_xdata_t *srv_xdata, struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "gw_post_init_service......\n");
    return CI_OK;
}

void gw_close_service()
{
        ci_debug_printf(5, "gw_close_service......\n");
}

void *gw_init_request_data(struct ci_request *req)
{
        ci_debug_printf(5, "gw_init_request_data......\n");
}

void gw_release_request_data(void *srv_data)
{
    ci_debug_printf(5, "gw_release_request_data......\n");
}

int gw_check_preview_handler(char *preview_data, int preview_data_len, struct ci_request *req)
{
    ci_debug_printf(5, "gw_check_preview_handler......\n");
    return CI_MOD_ALLOW204;
}

int gw_end_of_data_handler(struct ci_request *req)
{
    ci_debug_printf(5, "gw_end_of_data_handler......\n");
    return CI_MOD_DONE;
}

int gw_service_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, struct ci_request *req)
{
    ci_debug_printf(5, "gw_service_io......\n");
    return CI_OK;
}