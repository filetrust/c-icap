#ifndef gw_test_h
#define gw_test_h

#include "gw_body.h"

#define LOG_URL_SIZE 256

#define GW_RELOAD_ISTAG     "gw_test::reloadistag"

enum {NO_DECISION = -1, NO_SCAN=0,SCAN,VIR_SCAN};

struct av_file_types {
    int *scantypes;
    int *scangroups;
};

typedef struct gw_test_req_data {
    struct gw_body_data body;
    ci_request_t *req;
    int must_scanned ;
    int allow204;
    ci_membuf_t *error_page;
    char url_log[LOG_URL_SIZE];
    ci_off_t expected_size;
    struct{
	  int enable204;
	  int forcescan;
	  int sizelimit;
	  int mode;
    } args;
    ci_off_t max_object_size;
    int send_percent_bytes;
    ci_off_t start_send_after;
    int encoded;
} gw_test_req_data_t;

/*File types related functions*/
int av_file_types_init( struct av_file_types *ftypes);
void av_file_types_destroy( struct av_file_types *ftypes);

/*Configuration Functions*/
int cfg_ScanFileTypes(const char *directive, const char **argv, void *setdata);

#endif