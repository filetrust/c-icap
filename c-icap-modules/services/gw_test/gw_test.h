#ifndef gw_test_h
#define gw_test_h

#include "gw_body.h"

#define LOG_URL_SIZE 256

#define GW_RELOAD_ISTAG     "gw_test::reloadistag"

/* Used to initialise gw_status */
#define GW_STATUS_UNDEFINED 99

enum {NO_DECISION = -1, NO_SCAN=0,SCAN};

/* Used to define the gw_processing content */
enum {GW_PROCESSING_UNDEFINED = -1, GW_PROCESSING_NONE=0, GW_PROCESSING_SCANNED};

struct gw_file_types {
    int *scantypes;
    int *scangroups;
};

typedef struct gw_test_req_data {
    struct gw_body_data body;
    ci_request_t *req;
    int must_scanned ;
    int allow204;
    int gw_status;                  /* used to record the Glasswall processing status   */
    int gw_processing;              /* Used to record whether Glasswall processing is required */
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
int gw_file_types_init( struct gw_file_types *ftypes);
void gw_file_types_destroy( struct gw_file_types *ftypes);

#endif