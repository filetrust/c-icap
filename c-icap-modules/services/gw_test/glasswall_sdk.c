#include <wchar.h>
#include <string.h>
#include "glasswall_sdk.h"
#include "gwfile.h"
#include "gwfiletypes.h"
#include <stdlib.h>

#define GW_VERSION_SIZE 15
static char gw_version[GW_VERSION_SIZE];

void glasswall_sdk_init(glasswall_sdk_t* sdk)
{
    sdk->gw_file_config_xml = GWFileConfigXML;
    
    sdk->gw_memory_to_memory_protect = GWMemoryToMemoryProtect;   
    sdk->gw_file_protect = GWFileProtect;
    
    sdk->gw_determine_file_type_from_file = GWDetermineFileTypeFromFile;
    sdk->gw_determine_file_type_from_memory = GWDetermineFileTypeFromFileInMem;
    
    sdk->gw_file_done = GWFileDone;
    
    sdk->gw_file_version = GWFileVersion;
    
    gw_version[0]= '\0';
}

void glasswall_sdk_destroy(glasswall_sdk_t* sdk)
{
    free(sdk);
}

int gw_sdk_file_config_xml(glasswall_sdk_t* sdk, char* xmlstring){
    int status;
    int len = strlen(xmlstring);
    wchar_t* wide_xmlstring = malloc(len * (sizeof(wchar_t)+1));
    mbstowcs(wide_xmlstring, xmlstring, len);
    status = sdk->gw_file_config_xml(wide_xmlstring);
    free(wide_xmlstring);
    return status;
}

int gw_sdk_memory_to_memory_protect(glasswall_sdk_t* sdk, void *inputBuffer, size_t inputBufferLength, const char* type,void **outputFileBuffer, size_t *outputLength){
    wchar_t wcType[FILETYPE_SIZE];
    mbstowcs(wcType, type, FILETYPE_SIZE);
    return sdk->gw_memory_to_memory_protect(inputBuffer, inputBufferLength, wcType, outputFileBuffer, outputLength);
}

int gw_sdk_file_protect(glasswall_sdk_t* sdk, const char * inputFilePathName, const char* type, void **outputFileBuffer, size_t *outputLength){
    wchar_t wcPath[GW_BT_FILE_PATH_SIZE];
    wchar_t wcType[FILETYPE_SIZE];
    mbstowcs(wcPath, inputFilePathName, GW_BT_FILE_PATH_SIZE);
    mbstowcs(wcType, type, FILETYPE_SIZE);
    return sdk->gw_file_protect(wcPath, wcType, outputFileBuffer, outputLength);
}
    
int gw_sdk_determine_file_type_from_file(glasswall_sdk_t* sdk, const char* inputFilePathName){
    wchar_t filepath[GW_BT_FILE_PATH_SIZE];
    mbstowcs(filepath, inputFilePathName, GW_BT_FILE_PATH_SIZE);
    return sdk->gw_determine_file_type_from_file(filepath);     
}

int gw_sdk_determine_file_type_from_memory(glasswall_sdk_t* sdk, void* inputBuffer, size_t inputBufferSize){
    return sdk->gw_determine_file_type_from_memory(inputBuffer, inputBufferSize);
}

int gw_sdk_file_done(glasswall_sdk_t* sdk){
    return sdk->gw_file_done();
}

char *gw_sdk_file_version(glasswall_sdk_t* sdk){
    wchar_t* wsdkVersion = sdk->gw_file_version();
    wcstombs(gw_version, wsdkVersion, GW_VERSION_SIZE);
    return gw_version;
}
