#include <wchar.h>
#include <string.h>
#include "glasswall_sdk.h"
#include "gwfile.h"
#include "gwfiletypes.h"
#include <stdlib.h>

#define GW_VERSION_SIZE 15
#define GW_SDK_MUTEX_NAME "GW_SDK_MUTEX_NAME"
static char gw_version[GW_VERSION_SIZE];

void glasswall_sdk_init(glasswall_sdk_t* sdk)
{
    sdk->gw_file_config_xml = GWFileConfigXML;
    
    sdk->gw_memory_to_memory_protect = GWMemoryToMemoryProtect;   
    sdk->gw_file_protect = GWFileProtect;
    sdk->gw_file_to_file_protect = GWFileToFileProtect;
    
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
    int status;
    wchar_t wcType[FILETYPE_SIZE];
    mbstowcs(wcType, type, FILETYPE_SIZE);
    status = sdk->gw_memory_to_memory_protect(inputBuffer, inputBufferLength, wcType, outputFileBuffer, outputLength);
    return status;
}

int gw_sdk_file_protect(glasswall_sdk_t* sdk, const char * inputFilePathName, const char* type, void **outputFileBuffer, size_t *outputLength){
    int status;
    wchar_t wcPath[GW_BT_FILE_PATH_SIZE];
    wchar_t wcType[FILETYPE_SIZE];
    mbstowcs(wcPath, inputFilePathName, GW_BT_FILE_PATH_SIZE);
    mbstowcs(wcType, type, FILETYPE_SIZE);
    status =  sdk->gw_file_protect(wcPath, wcType, outputFileBuffer, outputLength);
    return status;
}

int gw_sdk_file_to_file_protect(glasswall_sdk_t* sdk, char*  inputFilePathName, char* type, char* outputFilePathName)
{
    int status;
    wchar_t wcInPath[GW_BT_FILE_PATH_SIZE];
    wchar_t wcOutPath[GW_BT_FILE_PATH_SIZE];
    wchar_t wcType[FILETYPE_SIZE];

    mbstowcs(wcInPath, inputFilePathName, GW_BT_FILE_PATH_SIZE);
    mbstowcs(wcOutPath, outputFilePathName, GW_BT_FILE_PATH_SIZE);
    mbstowcs(wcType, type, FILETYPE_SIZE);
    status =  sdk->gw_file_to_file_protect(wcInPath, wcType, wcOutPath);
    return status;
}

    
int gw_sdk_determine_file_type_from_file(glasswall_sdk_t* sdk, const char* inputFilePathName){
    int status;
    wchar_t filepath[GW_BT_FILE_PATH_SIZE];
    mbstowcs(filepath, inputFilePathName, GW_BT_FILE_PATH_SIZE);
    status = sdk->gw_determine_file_type_from_file(filepath);
    return status;
}

int gw_sdk_determine_file_type_from_memory(glasswall_sdk_t* sdk, void* inputBuffer, size_t inputBufferSize){
    int filetype;
    filetype =  sdk->gw_determine_file_type_from_memory(inputBuffer, inputBufferSize);
    return filetype;
}

int gw_sdk_file_done(glasswall_sdk_t* sdk){
    int status;
    status = sdk->gw_file_done();
    return status;
}

char *gw_sdk_file_version(glasswall_sdk_t* sdk){
    wchar_t* wsdkVersion = sdk->gw_file_version();
    wcstombs(gw_version, wsdkVersion, GW_VERSION_SIZE);
    return gw_version;
}
