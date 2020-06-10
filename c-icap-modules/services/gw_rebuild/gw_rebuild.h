#ifndef gw_rebuild_h
#define gw_rebuild_h

#include "gw_body.h"

#define LOG_URL_SIZE 256

#define GW_RELOAD_ISTAG     "gw_rebuild::reloadistag"

/* Used to initialise gw_status */
#define GW_STATUS_UNDEFINED 99

enum {NO_DECISION = -1, NO_SCAN=0,SCAN};

/* Used to define the gw_processing content */
enum {GW_PROCESSING_UNDEFINED = -1, GW_PROCESSING_NONE=0, GW_PROCESSING_SCANNED};

struct gw_file_types {
    int *scantypes;
    int *scangroups;
};

typedef struct gw_rebuild_req_data {
    gw_body_data_t body;
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
      int sizelimit;
      int mode;
    } args;
    ci_off_t max_object_size;
    int encoded;
} gw_rebuild_req_data_t;

/*File types related functions*/
int gw_file_types_init( struct gw_file_types *ftypes);
void gw_file_types_destroy( struct gw_file_types *ftypes);

#endif