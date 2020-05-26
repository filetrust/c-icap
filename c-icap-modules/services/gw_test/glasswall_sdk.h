#ifndef GLASSWALL_SDK_H
#define  GLASSWALL_SDK_H

#define GW_BT_FILE_PATH_SIZE 150
#define FILETYPE_SIZE 6

typedef struct glasswall_sdk {
	int (*gw_file_config_xml)(wchar_t * xmlstring);

	int (*gw_memory_to_memory_protect)(void *inputBuffer, size_t inputBufferLength, const wchar_t* wcType,void **outputFileBuffer, size_t *outputLength);
	int (*gw_memory_to_memory_analysis)(void *inputBuffer, size_t inputBufferLength, wchar_t* wcType, void **analysisFileBuffer, size_t *analysisFileBufferLength);
	
	int (*gw_file_protect)(const wchar_t * inputFilePathName, const wchar_t* wcType, void **outputFileBuffer, size_t *outputLength);
	int (*gw_file_analysis)(wchar_t * inputFilePathName, wchar_t* wcType, void **analysisFileBuffer, size_t *analysisFileBufferLength);
	
	int (*gw_determine_file_type_from_file)(const wchar_t* inputFilePathName);
	int (*gw_determine_file_type_from_memory)(void* inputBuffer, size_t inputBufferSize);

    int (*gw_file_done)(void);

	wchar_t *(*gw_file_version)(void);
	
} glasswall_sdk_t;

void glasswall_sdk_init(glasswall_sdk_t* sdk);
void glasswall_sdk_destroy(glasswall_sdk_t* sdk);

int gw_sdk_file_config_xml(glasswall_sdk_t* sdk, char * xmlstring);

int gw_sdk_memory_to_memory_protect(glasswall_sdk_t* sdk, void *inputBuffer, size_t inputBufferLength, const char* type,void **outputFileBuffer, size_t *outputLength);
int gw_sdk_memory_to_memory_analysis(glasswall_sdk_t* sdk, void *inputBuffer, size_t inputBufferLength, char* type, void **analysisFileBuffer, size_t *analysisFileBufferLength);

int gw_sdk_file_protect(glasswall_sdk_t* sdk, const char * inputFilePathName, const char* type, void **outputFileBuffer, size_t *outputLength);
int gw_sdk_file_analysis(glasswall_sdk_t* sdk, char * inputFilePathName, char* type, void **analysisFileBuffer, size_t *analysisFileBufferLength);

int gw_sdk_determine_file_type_from_file(glasswall_sdk_t* sdk, const char* inputFilePathName);
int gw_sdk_determine_file_type_from_memory(glasswall_sdk_t* sdk, void* inputBuffer, size_t inputBufferSize);

int gw_sdk_file_done(glasswall_sdk_t* sdk);

char *gw_sdk_file_version(glasswall_sdk_t* sdk);

#endif