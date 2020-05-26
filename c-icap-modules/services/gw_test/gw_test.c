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
#include "gwfile.h"
#include "gwfilestatus.h"
#include "gwfiletypes.h"
#include "filetypes.h"
#include "../../common.h"
#include "md5.h"
#include <errno.h>
#include <assert.h>
#include <locale.h>

void generate_error_page(gw_test_req_data_t *data, ci_request_t *req);
char *virus_scan_compute_name(ci_request_t *req);
static void rebuild_content_length(ci_request_t *req, struct gw_body_data *body);
/***********************************************************************************/
/* Module definitions                                                              */

static int SEND_PERCENT_DATA = 0;      /* By default will not send any bytes without check them before */
static int ALLOW204 = 1;
static ci_off_t MAX_OBJECT_SIZE = 5*1024*1024;
static ci_off_t START_SEND_AFTER = 0;
static int PASSONERROR = 0;
#define GW_VERSION_SIZE 15
#define AV_BT_FILE_PATH_SIZE 150

static struct ci_magics_db *magic_db = NULL;
static struct av_file_types SCAN_FILE_TYPES = {NULL, NULL};

char SDK_VERSION[GW_VERSION_SIZE];  

char *VIR_SAVE_DIR = NULL;
char *VIR_HTTP_SERVER = NULL;
int VIR_UPDATE_TIME = 15;

/*Statistic  Ids*/
static int AV_SCAN_REQS = -1;
static int AV_SCAN_BYTES = -1;
static int AV_VIRUSES_FOUND = -1;
static int AV_SCAN_FAILURES = -1;

/*********************/
/* Formating table   */
static int fmt_virus_scan_http_url(ci_request_t *req, char *buf, int len, const char *param);

struct ci_fmt_entry virus_scan_format_table [] = {
    {"%VU", "The HTTP url", fmt_virus_scan_http_url},
    { NULL, NULL, NULL}
};


/*virus_scan service extra data ... */
static ci_service_xdata_t *gw_test_xdata = NULL;

static int AVREQDATA_POOL = -1;

static int gw_test_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static int gw_test_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static void gw_test_close_service();
static int gw_test_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *);
static int gw_test_end_of_data_handler(ci_request_t *);
static void *gw_test_init_request_data(ci_request_t *req);
static void gw_test_release_request_data(void *data);
static int gw_test_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t *req);

/*Arguments parse*/
static void virus_scan_parse_args(gw_test_req_data_t *data, char *args);
/*Configuration Functions*/
int cfg_SendPercentData(const char *directive, const char **argv, void *setdata);
int cfg_av_set_str_vector(const char *directive, const char **argv, void *setdata);

/*General functions*/
static int get_filetype(ci_request_t *req, int *encoding);
static void set_istag(ci_service_xdata_t *srv_xdata);
static void cmd_reload_istag(const char *name, int type, void *data);
static int init_body_data(ci_request_t *req);

/*It is dangerous to pass directly fields of the limits structure in conf_variables,
  becouse in the feature some of this fields will change type (from int to unsigned int
  or from long to long long etc)
  I must use global variables and use the post_init_service function to fill the
  limits structure.
  But, OK let it go for the time ....
*/

/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
     {"SendPercentData",  &SEND_PERCENT_DATA, cfg_SendPercentData, NULL},
     {"MaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL},
     {"StartSendingDataAfter", &START_SEND_AFTER, ci_cfg_size_off, NULL},
     {"StartSendPercentDataAfter", &START_SEND_AFTER, ci_cfg_size_off, NULL},
     {"Allow204Responces", &ALLOW204, ci_cfg_onoff, NULL},
     {"PassOnError", &PASSONERROR, ci_cfg_onoff, NULL},
};


CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "gw_test",              /*Module name */
     "Glasswall Test service",        /*Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,        /*Service type responce or request modification */
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
    setlocale(LC_ALL, "");
    ci_debug_printf(5, "gw_test_init_service......\n");
    // Load the Glasswall library and get the version
    wchar_t* wsdkVersion = GWFileVersion();
    wcstombs(SDK_VERSION, wsdkVersion, GW_VERSION_SIZE);
        
    ci_debug_printf(4, "Glasswall SDK Version = %s\n", SDK_VERSION); 
    
     magic_db = server_conf->MAGIC_DB;
     av_file_types_init(&SCAN_FILE_TYPES);

     ci_debug_printf(10, "Going to initialize virus_scan\n");
     gw_test_xdata = srv_xdata;      /*Needed by db_reload command */
     ci_service_set_preview(srv_xdata, 1024);
     ci_service_enable_204(srv_xdata);
     ci_service_set_transfer_preview(srv_xdata, "*");

     /*Initialize object pools*/
     AVREQDATA_POOL = ci_object_pool_register("gw_test_req_data_t", sizeof(gw_test_req_data_t));

     if(AVREQDATA_POOL < 0) {
         ci_debug_printf(1, " gw_test_init_service: error registering object_pool gw_test_req_data_t\n");
         return CI_ERROR;
     }

     /*initialize statistic counters*/
     /* TODO:convert to const after fix ci_stat_* api*/
     char *stats_label = "Service virus_scan";
     AV_SCAN_REQS = ci_stat_entry_register("Requests scanned", STAT_INT64_T, stats_label);
     AV_SCAN_BYTES = ci_stat_entry_register("Body bytes scanned", STAT_KBS_T, stats_label);
     AV_VIRUSES_FOUND = ci_stat_entry_register("Viruses found", STAT_INT64_T, stats_label);
     AV_SCAN_FAILURES = ci_stat_entry_register("Scan failures", STAT_INT64_T, stats_label);

     return CI_OK;
}

int gw_test_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "gw_test_post_init_service......\n");
    set_istag(gw_test_xdata);
    register_command_extend(GW_RELOAD_ISTAG, ONDEMAND_CMD, NULL, cmd_reload_istag);
    return CI_OK;
}

void gw_test_close_service()
{
    ci_debug_printf(5, "gw_test_close_service......\n");
    av_file_types_destroy(&SCAN_FILE_TYPES);
    ci_object_pool_unregister(AVREQDATA_POOL);
}

void *gw_test_init_request_data(ci_request_t *req)
{
    int preview_size;
    gw_test_req_data_t *data;
     
    ci_debug_printf(5, "gw_test_init_request_data......\n"); 

     preview_size = ci_req_preview_size(req);

     if (req->args[0] != '\0') {
          ci_debug_printf(5, "service arguments:%s\n", req->args);
     }
     if (ci_req_hasbody(req)) {
          ci_debug_printf(5, "Request type: %d. Preview size:%d\n", req->type, preview_size);
          if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
               ci_debug_printf(1,
                               "Error allocation memory for service data!!!!!!!\n");
               return NULL;
          }
          memset(&data->body,0, sizeof(struct gw_body_data));
          data->error_page = NULL;
          data->url_log[0] = '\0';
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
               virus_scan_parse_args(data, req->args);
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
        ci_debug_printf(5, "Releasing virus_scan data.....\n");

        gw_body_data_destroy(&(((gw_test_req_data_t *) data)->body));

        if (((gw_test_req_data_t *) data)->error_page)
            ci_membuf_free(((gw_test_req_data_t *) data)->error_page);

        ci_object_pool_free(data);
     }
}


int gw_test_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *req)
{
     ci_off_t content_size = 0;

     gw_test_req_data_t *data = ci_service_data(req);

     ci_debug_printf(6, "OK; the preview data size is %d\n", preview_data_len);

     if (!data || !ci_req_hasbody(req)){
     ci_debug_printf(6, "No body data, allow 204\n");
          return CI_MOD_ALLOW204;
     }

    data->max_object_size = MAX_OBJECT_SIZE;
    data->send_percent_bytes = SEND_PERCENT_DATA;
    data->start_send_after = START_SEND_AFTER;

    /*Compute the expected size, will be used by must_scanned*/
    content_size = ci_http_content_length(req);
    data->expected_size = content_size;

    /*log objects url*/
    if (!ci_http_request_url(req, data->url_log, LOG_URL_SIZE)) {
        ci_debug_printf(2, "Failed to retrieve HTTP request URL\n");
    }

    if (preview_data_len == 0) {
        return CI_MOD_CONTINUE;
    }

    if (init_body_data(req) == CI_ERROR)
        return CI_ERROR;

    if (preview_data_len) {
        if (gw_body_data_write(&data->body, preview_data, preview_data_len,
                                ci_req_hasalldata(req)) == CI_ERROR)
        return CI_ERROR;
    }

    return CI_MOD_CONTINUE;
}


int virus_scan_write_to_net(char *buf, int len, ci_request_t *req)
{
    int bytes;
    gw_test_req_data_t *data = ci_service_data(req);
    if (!data)
        return CI_ERROR;

     /*if a virus found and no data sent, an inform page has already generated */

    if(data->body.type != AV_BT_NONE)
        bytes = gw_body_data_read(&data->body, buf, len);
    else
        bytes =0;
    return bytes;
}

int virus_scan_read_from_net(char *buf, int len, int iseof, ci_request_t *req)
{
     /*We can put here scanning hor jscripts and html and raw data ...... */
     int ret;
     int allow_transfer;
     gw_test_req_data_t *data = ci_service_data(req);
     if (!data)
          return CI_ERROR;

     if (data->must_scanned == NO_DECISION) {
         /*Build preview data
           TODO: move to c-icap/request.c ....
          */
         if (len) {
             ret = ci_buf_reset_size(&(req->preview_data), len > 1024? 1024 : len);
             assert(ret > 0);
             ci_buf_write(&(req->preview_data), buf, len > 1024 ? 1024 : len);
         }

         if (init_body_data(req) == CI_ERROR)
             return CI_ERROR;
     }
     assert(data->must_scanned != NO_DECISION);

     if (data->body.type == AV_BT_NONE) /*No body data? consume all content*/
     return len;

     if (data->must_scanned == NO_SCAN){
         /*if must not scanned then simply write the data and exit..... */
          return gw_body_data_write(&data->body, buf, len, iseof);
     }

     if (data->args.sizelimit
         && gw_body_data_size(&data->body) >= data->max_object_size) {
         ci_debug_printf(5, "Object bigger than max scanable file. \n");
          data->must_scanned = 0;

          if(data->args.mode == 1){
              /*We are in simple mode we can not send early ICAP responses. What?*/
              ci_debug_printf(1, "Object does not fit to max object size and early responses are not allowed! \n");
              return CI_ERROR;
          }
          else { /*Send early response.*/
              ci_req_unlock_data(req);      /*Allow ICAP to send data before receives the EOF....... */
              gw_body_data_unlock_all(&data->body);        /*Unlock all body data to continue send them..... */
          }

     }                          /*else Allow transfer data->send_percent_bytes of the data */
     else if (data->args.mode != 1 &&   /*not in the simple mode */
              data->start_send_after < gw_body_data_size(&data->body)) {
          ci_req_unlock_data(req);
          assert(data->send_percent_bytes >= 0 && data->send_percent_bytes <= 100);
          allow_transfer =
              (data->send_percent_bytes * (gw_body_data_size(&data->body) + len)) / 100;
          gw_body_data_unlock(&data->body, allow_transfer);
     }
     return gw_body_data_write(&data->body, buf, len, iseof);
}

int gw_test_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t *req)
{
     if (rbuf && rlen) {
          *rlen = virus_scan_read_from_net(rbuf, *rlen, iseof, req);
      if (*rlen == CI_ERROR)
           return CI_ERROR;
          /*else if (*rlen < 0) ignore*/
     }
     else if (iseof) {
     if (virus_scan_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
         return CI_ERROR;
     }

     if (wbuf && wlen) {
          *wlen = virus_scan_write_to_net(wbuf, *wlen, req);
     }
     return CI_OK;
}

static int rebuild_scan(ci_request_t *req, gw_test_req_data_t *data);
int gw_test_end_of_data_handler(ci_request_t *req)
{
    gw_test_req_data_t *data = ci_service_data(req);
    
    if (!data || data->body.type == AV_BT_NONE)
        return CI_MOD_DONE;
        
    if (rebuild_scan(req, data) == CI_ERROR) {
         ci_debug_printf(1, "Error while scanning for virus. Aborting....\n");
         return CI_ERROR;
    }   
    rebuild_content_length(req, &data->body);
    
    // Add header to show rebuilt status
    
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
        if (data->body.type == AV_BT_FILE) {
            zippedData = ci_simple_file_to_const_string(data->body.store.file);
            zippedDataLen = data->body.store.file->endpos;
            /**/
        } else {
            assert(data->body.type == AV_BT_MEM);
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
        ci_stat_uint64_inc(AV_SCAN_FAILURES, 1);
        if (PASSONERROR) {
            ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Let it pass due to PassOnError\n", err);
            return 1;
        }

        /*virus_scan_inflate_error always return a no null description*/
        ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Handle object as infected\n", err);
    }
    return 0;
}

wchar_t* SanitiseAll();
static int rebuild_scan(ci_request_t *req, gw_test_req_data_t *data)
{
    if (handle_deflated(data)) {
        /*TODO Must check for errors*/
        ci_debug_printf(4, "rebuild_scan\n");
        if (data->body.decoded){
            //scan_status = data->engine[i]->scan_simple_file(data->body.decoded, &data->virus_info);
            ci_debug_printf(4, "rebuild_scan: decoded\n")
            return CI_OK;
        }
        
        // Initialise the library with the content management policyl
        int returnStatus;
        returnStatus = GWFileConfigXML(SanitiseAll());
        if (returnStatus != eGwFileStatus_Success)
        {
            ci_debug_printf(4, "rebuild_scan: GWFileConfigXML error= %d\n", returnStatus);      
            return CI_ERROR;
        }       
        
        int filetypeIndex;
        const wchar_t * filetype;
        char filetypeString [5];    
        void *outputFileBuffer;
        size_t outputLength;
                
        if (data->body.type == AV_BT_FILE){
            ci_debug_printf(4, "rebuild_scan: AV_BT_FILE\n");
            wchar_t filepath [AV_BT_FILE_PATH_SIZE];
            mbstowcs(filepath, data->body.store.file->filename, AV_BT_FILE_PATH_SIZE);
            filetypeIndex = GWDetermineFileTypeFromFile(filepath);
            filetypeIndex = cli_ft(filetypeIndex);
            filetype = gwFileTypeResults[filetypeIndex];
            wcstombs(filetypeString, filetype, 5);
            ci_debug_printf(4, "rebuild_scan: filetype = %s\n", filetypeString);    
            
            returnStatus = GWFileProtect(filepath, filetype,
                                            &outputFileBuffer, &outputLength);
            if (returnStatus != eGwFileStatus_Success)
            {
                ci_debug_printf(4, "rebuild_scan: GWMemoryToMemoryProtect error= %d\n", returnStatus);      
                return CI_ERROR;
            }
            ci_debug_printf(4, "rebuild_scan: GWMemoryToMemoryProtect rebuilt size= %lu\n", outputLength);  
            gw_body_data_release(&data->body);
            gw_body_data_new(&data->body, AV_BT_FILE, outputLength);
            gw_body_data_write(&data->body, outputFileBuffer, outputLength, 1);            
        }
        else{ // if (data->body.type == AV_BT_MEM)
            ci_debug_printf(4, "rebuild_scan: AV_BT_MEM\n");
        
            filetypeIndex = GWDetermineFileTypeFromFileInMem(data->body.store.mem->buf, data->body.store.mem->bufsize); 
            filetypeIndex = cli_ft(filetypeIndex);
            filetype = gwFileTypeResults[filetypeIndex];
            wcstombs(filetypeString, filetype, 5);
            ci_debug_printf(4, "rebuild_scan: filetype = %s\n", filetypeString);        

            returnStatus = GWMemoryToMemoryProtect(data->body.store.mem->buf, data->body.store.mem->bufsize, filetype,
                                                    &outputFileBuffer, &outputLength);
            if (returnStatus != eGwFileStatus_Success)
            {
                ci_debug_printf(4, "rebuild_scan: GWMemoryToMemoryProtect error= %d\n", returnStatus);      
                return CI_ERROR;
            }
            
            ci_debug_printf(4, "rebuild_scan: GWMemoryToMemoryProtect rebuilt size= %lu\n", outputLength);  
            // Replace the original body
            //  this should be done using library functions working on gw_test_req_data_t, rather than here directly. 
            ci_membuf_free(data->body.store.mem);
            gw_body_data_new(&data->body, AV_BT_MEM, outputLength);
            gw_body_data_write(&data->body, outputFileBuffer, outputLength, 1);
            
        }

        ci_debug_printf(4, "rebuild_scanned\n");                

        /* we can not disinfect encoded files yet
           nor files which partialy sent back to client*/
        // if (data->body.decoded || ci_req_sent_data(req))
            // data->virus_info.disinfected = 0;

        // if (!scan_status) {
            // ci_stat_uint64_inc(AV_SCAN_FAILURES, 1);
            // ci_debug_printf(1, "Failed to scan web object\n");
            // /* We need to inform the caller proxy for the error,
               // to give the opportunity to stop using this broken
               // icap service.
             // */
            // if (!PASSONERROR)
                // return CI_ERROR;
        // }
    
        //  build_reply_headers(req, &data->virus_info);
        
        ci_stat_uint64_inc(AV_SCAN_REQS, 1);
        ci_stat_kbs_inc(AV_SCAN_BYTES, (int)gw_body_data_size(&data->body));
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
        gw_body_data_new(&(data->body), AV_BT_MEM, data->expected_size);
    else
        gw_body_data_new(&(data->body), AV_BT_FILE, data->args.sizelimit==0 ? 0 : data->max_object_size);
        /*Icap server can not send data at the begining.
        The following call does not needed because the c-icap
        does not send any data if the ci_req_unlock_data is not called:*/
        /* ci_req_lock_data(req);*/

        /* Let ci_simple_file api to control the percentage of data.
         For now no data can send */
    gw_body_data_lock_all(&(data->body));

    if (data->body.type == AV_BT_NONE)           /*Memory allocation or something else ..... */
        return CI_ERROR;

    return CI_OK;
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


    // lang = ci_membuf_attr_get(error_page, "lang");
    // if (lang) {
        // snprintf(buf, sizeof(buf), "Content-Language: %s", lang);
        // buf[sizeof(buf)-1] = '\0';
        // ci_http_response_add_header(req, buf);
    // }
    // else
        ci_http_response_add_header(req, "Content-Language: en");

 //   data->error_page = error_page;
}

int av_file_types_init( struct av_file_types *ftypes)
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

void av_file_types_destroy( struct av_file_types *ftypes)
{
    free(ftypes->scantypes);
    ftypes->scantypes = NULL;
    free(ftypes->scangroups);
    ftypes->scangroups = NULL;
}

static void cmd_reload_istag(const char *name, int type, void *data)
{
    ci_debug_printf(1, "recomputing istag ...\n");
    if (gw_test_xdata)
        set_istag(gw_test_xdata);
}

/***************************************************************************************/
/* Parse arguments function -
   Current arguments: allow204=on|off, force=on, sizelimit=off, mode=simple|vir|mixed
*/
void virus_scan_parse_args(gw_test_req_data_t *data, char *args)
{
     char *str;
     if ((str = strstr(args, "allow204="))) {
          if (strncmp(str + 9, "on", 2) == 0)
               data->args.enable204 = 1;
          else if (strncmp(str + 9, "off", 3) == 0)
               data->args.enable204 = 0;
     }
     if ((str = strstr(args, "force="))) {
          if (strncmp(str + 6, "on", 2) == 0)
               data->args.forcescan = 1;
     }
     if ((str = strstr(args, "sizelimit="))) {
          if (strncmp(str + 10, "off", 3) == 0)
               data->args.sizelimit = 0;
     }
     if ((str = strstr(args, "mode="))) {
          if (strncmp(str + 5, "simple", 6) == 0)
               data->args.mode = 1;
          else if (strncmp(str + 5, "vir", 3) == 0)
               data->args.mode = 2;
          else if (strncmp(str + 5, "mixed", 5) == 0)
               data->args.mode = 3;
          else if (strncmp(str + 5, "streamed", 8) == 0)
               data->args.mode = 4;
     }
}

void rebuild_content_length(ci_request_t *req, struct gw_body_data *bd)
{
    ci_off_t new_file_size = 0;
    char buf[256];
    ci_simple_file_t *body = NULL;
    ci_membuf_t *memBuf = NULL;

    if (bd->type == AV_BT_FILE) {
        body = bd->store.file;
        assert(body->readpos == 0);
        new_file_size = body->endpos;
    }
    else if (bd->type == AV_BT_MEM) {
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

int cfg_SendPercentData(const char *directive, const char **argv, void *setdata)
{
     int val = 0;
     char *end;
     if (argv == NULL || argv[0] == NULL) {
          ci_debug_printf(1, "Missing arguments in directive %s \n", directive);
          return 0;
     }
     errno = 0;
     val = strtoll(argv[0], &end, 10);
     if (errno != 0 || val < 0 || val > 100) {
          ci_debug_printf(1, "Invalid argument in directive %s \n", directive);
          return 0;
     }

     *((int *) setdata) = val;
     ci_debug_printf(2, "Setting parameter: %s=%d\n", directive, val);
     return 1;
}

int cfg_av_set_str_vector(const char *directive, const char **argv, void *setdata)
{
    int i;
    ci_str_vector_t **v = (ci_str_vector_t **) setdata;
    if (*v == NULL)
        *v = ci_str_vector_create(4096);
    for (i = 0; argv[i] != NULL; i++)
        (void)ci_str_vector_add(*v, argv[i]);

    if (i > 0)
        return 1;

    return 0;
}

/**************************************************************/
/* virus_scan templates  formating table                      */



int fmt_virus_scan_http_url(ci_request_t *req, char *buf, int len, const char *param)
{
    gw_test_req_data_t *data = ci_service_data(req);
    return snprintf(buf, len, "%s", data->url_log);
}

wchar_t* SanitiseAll()
{
    return L"<?xml version=\"1.0\" encoding=\"utf-8\" ?> <config>"
    L"<pdfConfig>"
    L"<javascript>sanitise</javascript>" 
    L"<acroform>sanitise</acroform>"
    L"<internal_hyperlinks>sanitise</internal_hyperlinks>"
    L"<external_hyperlinks>sanitise</external_hyperlinks>" 
    L"<embedded_files>sanitise</embedded_files>" 
    L"<metadata>sanitise</metadata>" 
    L"<actions_all>sanitise</actions_all>"
    L"</pdfConfig>"
    L"<wordConfig>"
    L"<metadata>sanitise</metadata>" 
    L"</wordConfig> </config>";
}

