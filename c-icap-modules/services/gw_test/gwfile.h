/**
* @file
**/
#ifndef DLL_GWFILE_H
#define DLL_GWFILE_H

#ifdef GLASSWALL_DLL
    #ifdef __GNUC__
        #define GLASSWALL_DLL_API __attribute__ ((visibility("default")))
    #elif _WIN32
        #define GLASSWALL_DLL_API __declspec(dllexport)
    #else
        #define GLASSWALL_DLL_API 
    #endif
#else
    #if _WIN32
        #define GLASSWALL_DLL_API __declspec(dllimport)
    #else
        #define GLASSWALL_DLL_API 
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /* Glasswall file DLL API */
    GLASSWALL_DLL_API int GWFileConfigXML(wchar_t * xmlstring);
    GLASSWALL_DLL_API int GWFileConfigGet(wchar_t **configurationBuffer, size_t *outputLength);
    GLASSWALL_DLL_API int GWFileConfigRevertToDefaults(void);

	GLASSWALL_DLL_API int GWMemoryToMemoryProtect(void *inputBuffer, size_t inputBufferLength, const wchar_t* wcType, void **outputFileBuffer, size_t *outputLength);
	GLASSWALL_DLL_API int GWMemoryToMemoryAnalysisAudit(void *inputBuffer, size_t inputBufferLength, wchar_t* wcType, void **analysisFileBuffer, size_t *analysisFileBufferLength);
	
	GLASSWALL_DLL_API int GWFileProtect(const wchar_t * inputFilePathName, const wchar_t* wcType, void **outputFileBuffer, size_t *outputLength);
	GLASSWALL_DLL_API int GWFileAnalysisAudit(wchar_t * inputFilePathName, wchar_t* wcType, void **analysisFileBuffer, size_t *analysisFileBufferLength);

    GLASSWALL_DLL_API int GWFileProcessStatus(unsigned int *glasswallProcessStatus);
		
	GLASSWALL_DLL_API int GWDetermineFileTypeFromFile(const wchar_t* inputFilePathName);
	GLASSWALL_DLL_API int GWDetermineFileTypeFromFileInMem(void* inputBuffer, size_t inputBufferSize);

    GLASSWALL_DLL_API int GWFileDone(void);

	GLASSWALL_DLL_API wchar_t *GWFileVersion(void);
	GLASSWALL_DLL_API wchar_t *GWFileProcessMsg(void);
	GLASSWALL_DLL_API wchar_t *GWFileErrorMsg(void);


#ifdef __cplusplus
}
#endif

#endif  /* DLL_GWFILE_H */
