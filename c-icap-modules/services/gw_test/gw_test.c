#include <wchar.h>
#include "c_icap/c-icap.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"
#include "c_icap/cfg_param.h"
#include "gw_test.h"
#include "c_icap/filetype.h"
#include "c_icap/ci_threads.h"
#include "c_icap/mem.h"
#include "c_icap/commands.h"
#include "c_icap/txt_format.h"
#include "c_icap/txtTemplate.h"
#include "c_icap/stats.h"
#include "glasswall_sdk.h"
#include "gwfilestatus.h"
#include "gwfiletypes.h"
#include "filetypes.h"
#include "../../common.h"
#include "md5.h"
#include <errno.h>
#include <assert.h>
#include <locale.h>

void generate_error_page(gw_test_req_data_t *data, ci_request_t *req);
static void rebuild_content_length(ci_request_t *req, gw_body_data_t *body);
void init_gw_sdk();
/***********************************************************************************/
/* Module definitions                                                              */

static int ALLOW204 = 1;
static ci_off_t MAX_OBJECT_SIZE = 5*1024*1024;
static int PASSONERROR = 0;
static int DATA_CLEANUP = 1;
#define GW_VERSION_SIZE 15
#define GW_BT_FILE_PATH_SIZE 150

static struct ci_magics_db *magic_db = NULL;
static struct gw_file_types SCAN_FILE_TYPES = {NULL, NULL};

char* SDK_VERSION;

/*Statistic  Ids*/
static int GW_SCAN_REQS = -1;
static int GW_SCAN_BYTES = -1;
static int GW_ISSUES_FOUND = -1;
static int GW_SCAN_FAILURES = -1;

/*********************/
/* Formating table   */
static int fmt_gw_test_http_url(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_gw_test_error_code(ci_request_t *req, char *buf, int len, const char *param);

struct ci_fmt_entry gw_test_report_format_table [] = {
    {"%GU", "The HTTP url", fmt_gw_test_http_url},
    {"%GE", "The Error code", fmt_gw_test_error_code},
    { NULL, NULL, NULL}
};

static glasswall_sdk_t* gw_sdk;


/*virus_scan service extra data ... */
static ci_service_xdata_t *gw_test_xdata = NULL;

static int GWREQDATA_POOL = -1;

static int gw_test_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static int gw_test_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static void gw_test_close_service();
static int gw_test_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *);
static int gw_test_end_of_data_handler(ci_request_t *);
static void *gw_test_init_request_data(ci_request_t *req);
static void gw_test_release_request_data(void *srv_data);
static int gw_test_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t *req);

/*Arguments parse*/
static void gw_test_parse_args(gw_test_req_data_t *data, char *args);
/*Configuration Functions*/
int cfg_ScanFileTypes(const char *directive, const char **argv, void *setdata);

/*General functions*/
static int get_filetype(ci_request_t *req, int *encoding);
static void set_istag(ci_service_xdata_t *srv_xdata);
static void cmd_reload_istag(const char *name, int type, void *data);
static int init_body_data(ci_request_t *req);

/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
     {"MaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL},
     {"Allow204Responses", &ALLOW204, ci_cfg_onoff, NULL},
     {"PassOnError", &PASSONERROR, ci_cfg_onoff, NULL},
     {"DataCleanup", &DATA_CLEANUP, ci_cfg_onoff, NULL},
     {"ScanFileTypes", &SCAN_FILE_TYPES, cfg_ScanFileTypes, NULL},     
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "gw_test",              /*Module name */
     "Glasswall Test service",        /*Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,        /*Service type response or request modification */
     gw_test_init_service,    /*init_service. */
     gw_test_post_init_service,   /*post_init_service. */
     gw_test_close_service,   /*close_service */
     gw_test_init_request_data,       /*init_request_data. */
     gw_test_release_request_data,    /*release request data */
     gw_test_check_preview_handler,
     gw_test_end_of_data_handler,
     gw_test_io,
     conf_variables,
     NULL
};

int gw_test_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf)
{
    init_gw_sdk();
    setlocale(LC_ALL, "");
    ci_debug_printf(3, "gw_test_init_service......\n");

    // Load the Glasswall library and get the version
    SDK_VERSION = gw_sdk_file_version(gw_sdk);

    ci_debug_printf(4, "Glasswall SDK Version = %s\n", SDK_VERSION);

     magic_db = server_conf->MAGIC_DB;
     gw_file_types_init(&SCAN_FILE_TYPES);

     gw_test_xdata = srv_xdata;      /*Needed by db_reload command */
     ci_service_set_preview(srv_xdata, 1024);
     ci_service_enable_204(srv_xdata);
     ci_service_set_transfer_preview(srv_xdata, "*");

     /*Initialize object pools*/
     GWREQDATA_POOL = ci_object_pool_register("gw_test_req_data_t", sizeof(gw_test_req_data_t));

     if(GWREQDATA_POOL < 0) {
         ci_debug_printf(1, " gw_test_init_service: error registering object_pool gw_test_req_data_t\n");
         return CI_ERROR;
     }

     /*initialize statistic counters*/
     /* TODO:convert to const after fix ci_stat_* api*/
     char *stats_label = "Service gw_test";
     GW_SCAN_REQS = ci_stat_entry_register("Requests scanned", STAT_INT64_T, stats_label);
     GW_SCAN_BYTES = ci_stat_entry_register("Body bytes scanned", STAT_KBS_T, stats_label);
     GW_ISSUES_FOUND = ci_stat_entry_register("Issues found", STAT_INT64_T, stats_label);
     GW_SCAN_FAILURES = ci_stat_entry_register("Scan failures", STAT_INT64_T, stats_label);

     return CI_OK;
}

int gw_test_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf)
{
    ci_debug_printf(3, "gw_test_post_init_service......\n");
    set_istag(gw_test_xdata);
    register_command_extend(GW_RELOAD_ISTAG, ONDEMAND_CMD, NULL, cmd_reload_istag);
    return CI_OK;
}

void gw_test_close_service()
{
    ci_debug_printf(3, "gw_test_close_service......\n");
    gw_file_types_destroy(&SCAN_FILE_TYPES);
    ci_object_pool_unregister(GWREQDATA_POOL);

    gw_sdk_file_done(gw_sdk);
}

void *gw_test_init_request_data(ci_request_t *req)
{
    int preview_size;
    gw_test_req_data_t *data;

    ci_debug_printf(3, "gw_test_init_request_data......\n");

     preview_size = ci_req_preview_size(req);

     if (req->args[0] != '\0') {
          ci_debug_printf(5, "service arguments:%s\n", req->args);
     }
     if (ci_req_hasbody(req)) {
          ci_debug_printf(5, "Request type: %d. Preview size:%d\n", req->type, preview_size);
          if (!(data = ci_object_pool_alloc(GWREQDATA_POOL))) {
               ci_debug_printf(1, "Error allocation memory for service data!!!!!!!\n");
               return NULL;
          }
          memset(&data->body,0, sizeof(gw_body_data_t));
          data->error_page = NULL;
          data->url_log[0] = '\0';
          data->gw_status = GW_STATUS_UNDEFINED;
          data->gw_processing = GW_PROCESSING_UNDEFINED;
          data->must_scanned = SCAN;
          if (ALLOW204)
               data->args.enable204 = 1;
          else
               data->args.enable204 = 0;
          data->args.forcescan = 0;
          data->args.sizelimit = 1;
          data->args.mode = 0;

          if (req->args[0] != '\0') {
               ci_debug_printf(5, "service arguments:%s\n", req->args);
               gw_test_parse_args(data, req->args);
          }
          if (data->args.enable204 && ci_allow204(req))
               data->allow204 = 1;
          else
               data->allow204 = 0;
          data->req = req;

          return data;
     }
     return NULL;
}

void gw_test_release_request_data(void *data)
{
    if (data) {
        ci_debug_printf(3, "Releasing gw_test data.....\n");
        gw_test_req_data_t *requestData = (gw_test_req_data_t *) data;
        if (DATA_CLEANUP)
        {            
            gw_body_data_destroy(&requestData->body);
        }
        else
        {
            if (requestData->body.type == GW_BT_MEM)
                gw_body_data_destroy(&requestData->body);
            else
                ci_debug_printf(3, "Leaving gw_test data body.....\n");
        }

        if (((gw_test_req_data_t *) data)->error_page)
            ci_membuf_free(((gw_test_req_data_t *) data)->error_page);

        ci_object_pool_free(data);
     }
}
static int must_scanned(ci_request_t *req, char *preview_data, int preview_data_len);
int gw_test_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *req)
{
     ci_off_t content_size = 0;

     gw_test_req_data_t *data = ci_service_data(req);

     ci_debug_printf(3, "gw_test_check_preview_handler; preview data size is %d\n", preview_data_len);

     if (!data || !ci_req_hasbody(req)){
        ci_debug_printf(6, "No body data, allow 204\n");
        return CI_MOD_ALLOW204;
     }

    data->max_object_size = MAX_OBJECT_SIZE;

    /*Compute the expected size, will be used by must_scanned*/
    content_size = ci_http_content_length(req);
    data->expected_size = content_size;
    ci_debug_printf(6, "gw_test_check_preview_handler: expected_size is %ld\n", content_size);

    /*log objects url*/
    if (!ci_http_request_url(req, data->url_log, LOG_URL_SIZE)) {
        ci_debug_printf(2, "Failed to retrieve HTTP request URL\n");
    }

    if (init_body_data(req) == CI_ERROR)
        return CI_ERROR;
    
    if (preview_data_len == 0) {
        return CI_MOD_CONTINUE;
    }
    
    if (must_scanned(req, preview_data, preview_data_len) == NO_SCAN){
        ci_debug_printf(6, "Not in scan list. Allow it...... \n");
        return CI_MOD_ALLOW204;
    }
    
    if (preview_data_len) {
        if (gw_body_data_write(&data->body, preview_data, preview_data_len,
                                ci_req_hasalldata(req)) == CI_ERROR)
        return CI_ERROR;
    }
    ci_debug_printf(6, "gw_test_check_preview_handler: gw_body_data_write data_len %d\n", preview_data_len);

    return CI_MOD_CONTINUE;
}

int gw_test_write_to_net(char *buf, int len, ci_request_t *req)
{
    ci_debug_printf(9, "gw_test_write_to_net; buf len is %d\n", len);

    int bytes;
    gw_test_req_data_t *data = ci_service_data(req);
    if (!data)
        return CI_ERROR;

    if(data->body.type != GW_BT_NONE)
        bytes = gw_body_data_read(&data->body, buf, len);
    else
        bytes =0;

    ci_debug_printf(9, "gw_test_write_to_net; write bytes is %d\n", bytes);

    return bytes;
}

int gw_test_read_from_net(char *buf, int len, int iseof, ci_request_t *req)
{
    ci_debug_printf(7, "gw_test_read_from_net; buf len is %d, iseof is %d\n", len, iseof);

     //int ret;
    // int allow_transfer;
     gw_test_req_data_t *data = ci_service_data(req);
     if (!data)
          return CI_ERROR;

     if (data->body.type == GW_BT_NONE) /*No body data? consume all content*/
        return len;

     if (data->args.sizelimit
         && gw_body_data_size(&data->body) >= data->max_object_size) {
         ci_debug_printf(2, "Object bigger than max scanable file. \n");

        /*TODO: Raise an error report rather than just raise an error */
        return CI_ERROR;
     } 
     ci_debug_printf(8, "gw_test_read_from_net:Writing to data->body, %d bytes \n", len);

     return gw_body_data_write(&data->body, buf, len, iseof);
}

int gw_test_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req)
{
    char printBuffer[100];
    char tempBuffer[20];
    printBuffer[0] = '\0';
    strcat(printBuffer, "gw_test_io, ");

    if (wlen) {
        sprintf(tempBuffer, "wlen=%d, ", *wlen);
        strcat(printBuffer, tempBuffer);
    }
    if (rlen) {
        sprintf(tempBuffer, "rlen=%d, ", *rlen);
        strcat(printBuffer, tempBuffer);
    }
    sprintf(tempBuffer, "iseof=%d\n", iseof);
    strcat(printBuffer, tempBuffer);
    ci_debug_printf(9, "%s", printBuffer);

     if (rbuf && rlen) {
          *rlen = gw_test_read_from_net(rbuf, *rlen, iseof, req);
      if (*rlen == CI_ERROR)
           return CI_ERROR;
          /*else if (*rlen < 0) ignore*/
     }
     else if (iseof) {
     if (gw_test_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
         return CI_ERROR;
     }

     if (wbuf && wlen) {
          *wlen = gw_test_write_to_net(wbuf, *wlen, req);
     }
     return CI_OK;
}

static int rebuild_scan(ci_request_t *req, gw_test_req_data_t *data);
int gw_test_end_of_data_handler(ci_request_t *req)
{
    ci_debug_printf(3, "gw_test_end_of_data_handler\n");

    gw_test_req_data_t *data = ci_service_data(req);

    if (!data || data->body.type == GW_BT_NONE){
        data->gw_processing = GW_PROCESSING_NONE;
        return CI_MOD_DONE;
    }

    if (rebuild_scan(req, data) == CI_ERROR) {
         ci_debug_printf(1, "Error while scanning. Aborting....\n");
         return CI_ERROR;
    }

    if (data->gw_status == eGwFileStatus_Success){
        if(data->gw_processing == GW_PROCESSING_SCANNED){
            ci_request_set_str_attribute(req,"gw_test:action", "rebuilt");
            ci_debug_printf(5, "gw_test_end_of_data_handler GW_PROCESSING_SCANNED\n");
            rebuild_content_length(req, &data->body);
        } else if (data->gw_processing == GW_PROCESSING_NONE){
            if (data->allow204 && !ci_req_sent_data(req)) {
                ci_request_set_str_attribute(req,"gw_test:action", "none");
                ci_debug_printf(5, "gw_test_end_of_data_handler GW_PROCESSING_NONE\n");
                return CI_MOD_ALLOW204;
            } 
            ci_debug_printf(5, "gw_test_end_of_data_handler GW_PROCESSING_NONE done\n");
        } else {
            ci_debug_printf(1, "Unexpected gw_processing status %d\n", data->gw_processing);
        }
    } else if (data->gw_status == eGwFileStatus_Error){
          generate_error_page(data, req);
          ci_request_set_str_attribute(req,"virus_scan:action", "blocked");
          ci_debug_printf(5, "gw_test_end_of_data_handler eGwFileStatus_Error\n");
    } else{
        if (data->gw_processing == GW_PROCESSING_NONE){
            if (data->allow204 && !ci_req_sent_data(req)) {
                ci_request_set_str_attribute(req,"gw_test:action", "none");
                ci_debug_printf(5, "gw_test_end_of_data_handler GW_PROCESSING_NONE\n");
                return CI_MOD_ALLOW204;            
            } 
            ci_debug_printf(5, "gw_test_end_of_data_handler GW_PROCESSING_NONE done\n");
        }
        else{
            generate_error_page(data, req);
            ci_debug_printf(1, "Unexpected gw_status %d\n", data->gw_status);
            ci_request_set_str_attribute(req,"virus_scan:action", "errored");
        }
    }

    if (data->error_page)
    {
        ci_debug_printf(5, "Error page to send\n");
        int error_report_size;
        error_report_size = ci_membuf_size(data->error_page);
   
        gw_body_data_destroy(&data->body);
        gw_body_data_new(&data->body, GW_BT_MEM, error_report_size);
        gw_body_data_write(&data->body, data->error_page->buf, error_report_size, 1);
        rebuild_content_length(req, &data->body);
    }
       
    ci_req_unlock_data(req);
    gw_body_data_unlock_all(&data->body);

    return CI_MOD_DONE;
}

static int handle_deflated(gw_test_req_data_t *data)
{
    const char *err = NULL;
    /*
      Normally antiviruses can not handle deflate encoding, because there is not
      any way to recognize them. So try to uncompress deflated files before pass them
      to the antivirus engine.
    */
    int ret = CI_UNCOMP_OK;

    if (data->encoded != CI_ENCODE_DEFLATE
#if defined(HAVE_CICAP_BROTLI)
        && data->encoded != CI_ENCODE_BROTLI
#endif
       )
        return 1;

    if ((data->body.decoded = ci_simple_file_new(0))) {
        const char *zippedData = NULL;
        size_t zippedDataLen = 0;
        if (data->body.type == GW_BT_FILE) {
            zippedData = ci_simple_file_to_const_string(data->body.store.file);
            zippedDataLen = data->body.store.file->endpos;
            /**/
        } else {
            assert(data->body.type == GW_BT_MEM);
            zippedData = data->body.store.mem->buf;
            zippedDataLen = data->body.store.mem->endpos;
        }
        if (zippedData) {
            ci_debug_printf(3, "Zipped data %p of size %ld, encoding method: %s\n", zippedData, (long int) zippedDataLen, (data->encoded == CI_ENCODE_DEFLATE ? "deflate" : "brotli"));
            ret = gw_decompress_to_simple_file(data->encoded, zippedData, zippedDataLen, data->body.decoded, MAX_OBJECT_SIZE);
            ci_debug_printf(3, "Scan from unzipped file %s of size %lld\n", data->body.decoded->filename, (long long int)data->body.decoded->endpos);
        }
    } else {
        ci_debug_printf(1, "Enable to create temporary file to decode deflated file!\n");
        ret = CI_UNCOMP_ERR_ERROR;
    }


    if (ret ==CI_UNCOMP_OK)
        return 1;

    if (ret == CI_UNCOMP_ERR_NONE) /*Exceeds the maximum allowed size*/
        data->must_scanned = NO_SCAN;
    else {
        /*Probably corrupted object. Handle it as virus*/
#if defined(HAVE_CICAP_DECOMPRESS_ERROR)
        err = ci_decompress_error(ret);
#else
        err = ci_inflate_error(ret);
#endif
        ci_stat_uint64_inc(GW_SCAN_FAILURES, 1);
        if (PASSONERROR) {
            ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Let it pass due to PassOnError\n", err);
            return 1;
        }

        ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Handle object as infected\n", err);
    }
    return 0;
}

int glasswall_processable(const int filetypeIndex);
char* sanitise_all();
static int rebuild_scan(ci_request_t *req, gw_test_req_data_t *data)
{
    if (handle_deflated(data)) {
        /*TODO Must check for errors*/
        ci_debug_printf(5, "rebuild_scan\n");
        if (data->body.decoded){
            ci_debug_printf(2, "rebuild_scan: decoded, no processing\n")
            data->gw_processing = GW_PROCESSING_NONE;
            return CI_OK;
        }

        int returnStatus;

        data->gw_processing = GW_PROCESSING_SCANNED;

        returnStatus = gw_sdk_file_config_xml(gw_sdk, sanitise_all());
        if (returnStatus != eGwFileStatus_Success)
        {
            ci_debug_printf(5, "rebuild_scan: GWFileConfigXML error= %d\n", returnStatus);
            data->gw_status = returnStatus;
            return CI_ERROR;
        }

        int filetypeIndex;
        const char* filetype;
        void *outputFileBuffer;
        size_t outputLength;

        if (data->body.type == GW_BT_FILE){
            ci_debug_printf(5, "rebuild_scan: GW_BT_FILE\n");

            filetypeIndex = gw_sdk_determine_file_type_from_file(gw_sdk, data->body.store.file->filename);
            if (glasswall_processable(filetypeIndex)){
                filetypeIndex = cli_ft(filetypeIndex);
                filetype = gwFileTypeResults[filetypeIndex];
                ci_debug_printf(5, "rebuild_scan: filetype = %s\n", filetype);
                data->gw_processing = GW_PROCESSING_SCANNED;

                returnStatus = gw_sdk_file_protect(gw_sdk, data->body.store.file->filename, filetype,
                                                &outputFileBuffer, &outputLength);
                data->gw_status = returnStatus;

                if (returnStatus == eGwFileStatus_InternalError)
                {
                    ci_debug_printf(5, "rebuild_scan: GWFileProtect error= %d\n", returnStatus);
                    return CI_ERROR;
                }

                if (returnStatus == eGwFileStatus_Success){
                    ci_debug_printf(5, "rebuild_scan: GWFileProtect rebuilt size= %lu\n", outputLength);
                    gw_body_data_replace_body(&data->body, outputFileBuffer, outputLength);
                }
            }
            else{
                ci_debug_printf(5, "rebuild_scan: Filetype index %d no processing\n", filetypeIndex);
                data->gw_processing = GW_PROCESSING_NONE;
                return CI_OK;
            }
        }
        else{
            ci_debug_printf(5, "rebuild_scan: GW_BT_MEM\n");

            filetypeIndex = gw_sdk_determine_file_type_from_memory(gw_sdk, data->body.store.mem->buf, data->body.store.mem->bufsize);
            if (glasswall_processable(filetypeIndex)){
                filetypeIndex = cli_ft(filetypeIndex);
                filetype = gwFileTypeResults[filetypeIndex];
                ci_debug_printf(5, "rebuild_scan: filetype = %s\n", filetype);
                data->gw_processing = GW_PROCESSING_SCANNED;

                returnStatus = gw_sdk_memory_to_memory_protect(gw_sdk, data->body.store.mem->buf, data->body.store.mem->bufsize, filetype,
                                                        &outputFileBuffer, &outputLength);
                data->gw_status = returnStatus;

                if (returnStatus == eGwFileStatus_InternalError)
                {
                    ci_debug_printf(4, "rebuild_scan: GWMemoryToMemoryProtect error= %d\n", returnStatus);
                    return CI_ERROR;
                }
                if (returnStatus == eGwFileStatus_Success){
                    ci_debug_printf(5, "rebuild_scan: GWMemoryToMemoryProtect rebuilt size= %lu\n", outputLength);
                    gw_body_data_replace_body(&data->body, outputFileBuffer, outputLength);
                }
            }
            else{
                ci_debug_printf(5, "rebuild_scan: GW_BT_MEM : Filetype index %d no processing\n", filetypeIndex);
                data->gw_processing = GW_PROCESSING_NONE;
                return CI_OK;
            }
        }

        if (returnStatus == eGwFileStatus_Error)
        {
            ci_debug_printf(5, "rebuild_scan: eGwFileStatus_Error\n");
        }

        ci_debug_printf(5, "rebuild_scanned\n");

        ci_stat_uint64_inc(GW_SCAN_REQS, 1);
        ci_stat_kbs_inc(GW_SCAN_BYTES, (int)gw_body_data_size(&data->body));
    }
    return CI_OK;
}

/*******************************************************************************/
/* Other  functions                                                            */

void set_istag(ci_service_xdata_t *srv_xdata)
{
     ci_service_set_istag(srv_xdata, SDK_VERSION);
}

int get_filetype(ci_request_t *req, int *iscompressed)
{
    int filetype;
    /*Use the ci_magic_req_data_type which caches the result*/
    filetype = ci_magic_req_data_type(req, iscompressed);
    return filetype;
}

static int init_body_data(ci_request_t *req)
{
    int scan_from_mem;
    gw_test_req_data_t *data = ci_service_data(req);
    assert(data);

    scan_from_mem = 1;

    if (scan_from_mem &&
        data->expected_size > 0 && data->expected_size < CI_BODY_MAX_MEM)
        gw_body_data_new(&(data->body), GW_BT_MEM, data->expected_size);
    else
        gw_body_data_new(&(data->body), GW_BT_FILE, data->args.sizelimit==0 ? 0 : data->max_object_size);
        /*Icap server can not send data at the begining.
        The following call does not needed because the c-icap
        does not send any data if the ci_req_unlock_data is not called:*/
        /* ci_req_lock_data(req);*/

        /* Let ci_simple_file api to control the percentage of data.
         For now no data can send */
    gw_body_data_lock_all(&(data->body));

    if (data->body.type == GW_BT_NONE)           /*Memory allocation or something else ..... */
        return CI_ERROR;

    return CI_OK;
}

int must_scanned(ci_request_t *req, char *preview_data, int preview_data_len)
{
    int type, i;
    int *file_groups;
    const struct gw_file_types *configured_file_types = &SCAN_FILE_TYPES;
    gw_test_req_data_t *data  = ci_service_data(req);
    int file_type = get_filetype(req, &data->encoded);

     /*By default do not scan*/
     type = NO_SCAN;  
     
    if (preview_data_len == 0 || file_type < 0) {
        if (ci_http_request_url(req, data->url_log, LOG_URL_SIZE) <= 0)
            strcpy(data->url_log, "-");

        ci_debug_printf(1, "WARNING! %s, can not get required info to scan url: %s\n",
             (preview_data_len == 0? "No preview data" : "Error computing file type"),
             data->url_log);
    }
    else
    {
        file_groups = ci_data_type_groups(magic_db, file_type);
        i = 0;
        if (file_groups) {
            while ( i < MAX_GROUPS && file_groups[i] >= 0) {
                assert(file_groups[i] < ci_magic_groups_num(magic_db));
                if ((type = configured_file_types->scangroups[file_groups[i]]) > 0)                    
                    break;
                i++;
            }
        }

        if (type == NO_SCAN) {
            assert(file_type < ci_magic_types_num(magic_db));
            type = configured_file_types->scantypes[file_type];
        }        
    }
    return type;
}


void generate_error_page(gw_test_req_data_t *data, ci_request_t *req)
{
    ci_membuf_t *error_page;
    char buf[1024];
    const char *lang;

    if ( ci_http_response_headers(req))
         ci_http_response_reset_headers(req);
    else
         ci_http_response_create(req, 1, 1);
    ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden");
    ci_http_response_add_header(req, "Server: C-ICAP");
    ci_http_response_add_header(req, "Connection: close");
    ci_http_response_add_header(req, "Content-Type: text/html");

    error_page = ci_txt_template_build_content(req, "gw_test", "POLICY_ISSUE",
                           gw_test_report_format_table);

    lang = ci_membuf_attr_get(error_page, "lang");
    if (lang) {
        snprintf(buf, sizeof(buf), "content-language: %s", lang);
        buf[sizeof(buf)-1] = '\0';
        ci_http_response_add_header(req, buf);
    }
    else
        ci_http_response_add_header(req, "Content-Language: en");

    data->error_page = error_page;
}

int gw_file_types_init( struct gw_file_types *ftypes)
{
    int i;
    ftypes->scantypes = (int *) malloc(ci_magic_types_num(magic_db) * sizeof(int));
    ftypes->scangroups = (int *) malloc(ci_magic_groups_num(magic_db) * sizeof(int));

    if (!ftypes->scantypes || !ftypes->scangroups)
        return 0;

    for (i = 0; i < ci_magic_types_num(magic_db); i++)
        ftypes->scantypes[i] = 0;
    for (i = 0; i < ci_magic_groups_num(magic_db); i++)
        ftypes->scangroups[i] = 0;
    return 1;
}

void gw_file_types_destroy( struct gw_file_types *ftypes)
{
    free(ftypes->scantypes);
    ftypes->scantypes = NULL;
    free(ftypes->scangroups);
    ftypes->scangroups = NULL;
}

static void cmd_reload_istag(const char *name, int type, void *data)
{
    ci_debug_printf(5, "recomputing istag ...\n");
    if (gw_test_xdata)
        set_istag(gw_test_xdata);
}

/***************************************************************************************/
/* Parse arguments function -
   Current arguments: allow204=on|off, sizelimit=off
*/
void gw_test_parse_args(gw_test_req_data_t *data, char *args)
{
     char *str;
     if ((str = strstr(args, "allow204="))) {
          if (strncmp(str + 9, "on", 2) == 0)
               data->args.enable204 = 1;
          else if (strncmp(str + 9, "off", 3) == 0)
               data->args.enable204 = 0;
     }

     if ((str = strstr(args, "sizelimit="))) {
          if (strncmp(str + 10, "off", 3) == 0)
               data->args.sizelimit = 0;
     }

}

void rebuild_content_length(ci_request_t *req, gw_body_data_t *bd)
{
    ci_off_t new_file_size = 0;
    char buf[256];
    ci_simple_file_t *body = NULL;
    ci_membuf_t *memBuf = NULL;

    if (bd->type == GW_BT_FILE) {
        body = bd->store.file;
        assert(body->readpos == 0);
        new_file_size = body->endpos;
    }
    else if (bd->type == GW_BT_MEM) {
        memBuf = bd->store.mem;
        new_file_size = memBuf->endpos;
    }
    else /*do nothing....*/
        return;

    ci_debug_printf(5, "Body data size changed to new size %"  PRINTF_OFF_T "\n",
                    (CAST_OFF_T)new_file_size);

    snprintf(buf, sizeof(buf), "Content-Length: %" PRINTF_OFF_T, (CAST_OFF_T)new_file_size);
    ci_http_response_remove_header(req, "Content-Length");
    ci_http_response_add_header(req, buf);
}

/****************************************************************************************/
/*Configuration Functions                                                               */

int cfg_ScanFileTypes(const char *directive, const char **argv, void *setdata)
{
     int i, id;
     int type = NO_SCAN;
     struct gw_file_types *ftypes = (struct gw_file_types *)setdata;
     if (!ftypes)
         return 0;

     if (strcmp(directive, "ScanFileTypes") == 0)
          type = SCAN;
     else
          return 0;

     for (i = 0; argv[i] != NULL; i++) {
          if ((id = ci_get_data_type_id(magic_db, argv[i])) >= 0)
               ftypes->scantypes[id] = type;
          else if ((id = ci_get_data_group_id(magic_db, argv[i])) >= 0)
               ftypes->scangroups[id] = type;
          else
               ci_debug_printf(1, "Unknown data type %s \n", argv[i]);

     }

     ci_debug_printf(2, "scan data for %s scanning of type: ",
                     (type == 1 ? "simple" : "vir_mode"));
     for (i = 0; i < ci_magic_types_num(magic_db); i++) {
          if (ftypes->scantypes[i] == type)
               ci_debug_printf(2, ",%s", ci_data_type_name(magic_db, i));
     }
     for (i = 0; i < ci_magic_groups_num(magic_db); i++) {
          if (ftypes->scangroups[i] == type)
               ci_debug_printf(2, ",%s", ci_data_group_name(magic_db, i));
     }
     ci_debug_printf(1, "\n");
     return 1;
}

/**************************************************************/
/* gw_test templates  formating table                         */

int fmt_gw_test_http_url(ci_request_t *req, char *buf, int len, const char *param)
{
    gw_test_req_data_t *data = ci_service_data(req);
    return snprintf(buf, len, "%s", data->url_log);
}

static int fmt_gw_test_error_code(ci_request_t *req, char *buf, int len, const char *param)
{
    gw_test_req_data_t *data = ci_service_data(req);
    return snprintf(buf, len, "%d", data->gw_status);
}

void init_gw_sdk()
{
    gw_sdk = malloc(sizeof(glasswall_sdk_t));
    glasswall_sdk_init(gw_sdk);
}

char* sanitise_all()
{
    return "<?xml version=\"1.0\" encoding=\"utf-8\" ?> <config>"
    "<pdfConfig>"
    "<javascript>sanitise</javascript>"
    "<acroform>sanitise</acroform>"
    "<internal_hyperlinks>sanitise</internal_hyperlinks>"
    "<external_hyperlinks>sanitise</external_hyperlinks>"
    "<embedded_files>sanitise</embedded_files>"
    "<metadata>sanitise</metadata>"
    "<actions_all>sanitise</actions_all>"
    "<embedded_images>sanitise</embedded_images>"
    "</pdfConfig>"
    "<wordConfig>"
    "<metadata>sanitise</metadata>"
    "<embedded_files>sanitise</embedded_files>"
    "<dynamic_data_exchange>sanitise</dynamic_data_exchange>"
    "<embedded_images>sanitise</embedded_images>"
    "<internal_hyperlinks>sanitise</internal_hyperlinks>"
    "<external_hyperlinks>sanitise</external_hyperlinks>"
    "<macros>sanitise</macros>"
    "<review_comments>sanitise</review_comments>"
    "</wordConfig>"
    "<pptConfig>"
    "<embedded_files>sanitise</embedded_files>"
    "<embedded_images>sanitise</embedded_images>"
    "<internal_hyperlinks>sanitise</internal_hyperlinks>"
    "<external_hyperlinks>sanitise</external_hyperlinks>"
    "<macros>sanitise</macros>"
    "<metadata>sanitise</metadata>"
    "<review_comments>sanitise</review_comments>"
    "</pptConfig>"
    "<xlsConfig>"
    "<embedded_files>sanitise</embedded_files>"
    "<dynamic_data_exchange>sanitise</dynamic_data_exchange>"
    "<embedded_images>sanitise</embedded_images>"
    "<internal_hyperlinks>sanitise</internal_hyperlinks>"
    "<external_hyperlinks>sanitise</external_hyperlinks>"
    "<macros>sanitise</macros>"
    "<metadata>sanitise</metadata>"
    "<review_comments>sanitise</review_comments>"
    "</xlsConfig>"
    "</config>";
}

int glasswall_processable(const int filetypeIndex)
{
    if (ft_pdf <= filetypeIndex && filetypeIndex <= ft_bmp)
        return 1;
    return 0;
}

