#include <stdio.h>  
#include <stdlib.h>

#include "gwfilestatus.h"
#include "glasswall_sdk.h"
#include "gwfiletypes.h"
#include "filetypes.h"

#define INPUT_FILE 1
#define OUTPUT_FILE 2

static glasswall_sdk_t* gw_sdk;

/* Prototypes */
void init_gw_sdk();
int rebuild_scan(char* input_path, char* output_path);
char* sanitise_all();
int glasswall_processable(const int filetypeIndex);

int main(int argc, char *argv[] )  {  
    int rebuild_status;
    init_gw_sdk();
    if(argc < 3){  
        printf("ERROR: incorrect number of arguments (%d)\n", argc);
        exit (EXIT_FAILURE);
    }  
    printf("Rebuilding from %s to %s\n", argv[INPUT_FILE], argv[OUTPUT_FILE]);
    rebuild_status = rebuild_scan(argv[INPUT_FILE], argv[OUTPUT_FILE]);

    gw_sdk_file_done(gw_sdk);
    exit (rebuild_status==eGwFileStatus_Success?EXIT_SUCCESS:EXIT_FAILURE);
}  

int rebuild_scan(char* input_path, char* output_path)
{
    int processing_status = eGwFileStatus_Success;
    processing_status = gw_sdk_file_config_xml(gw_sdk, sanitise_all());
    
    printf("gw_sdk_file_config_xml %d\n", processing_status);   
    if (processing_status == eGwFileStatus_Success)
    {       
        int filetypeIndex;
        char *filetype;
        filetypeIndex = gw_sdk_determine_file_type_from_file(gw_sdk, input_path);
        printf("gw_sdk_determine_file_type_from_file %d\n", filetypeIndex);   

        if (glasswall_processable(filetypeIndex)){
            filetypeIndex = cli_ft(filetypeIndex);
            filetype = gwFileTypeResults[filetypeIndex];
            printf("gwFileTypeResults %s\n", filetype);   

            processing_status = gw_sdk_file_to_file_protect(gw_sdk, input_path, filetype, output_path);           
            printf("gw_sdk_file_to_file_protect %d\n", processing_status);   
        }
    }

    return processing_status;

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