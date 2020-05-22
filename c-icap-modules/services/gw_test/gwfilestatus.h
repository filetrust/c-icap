#ifndef DLL_GWFILESTATUS_H
#define DLL_GWFILESTATUS_H

/**
*
*   @addtogroup gwFileProcessingResults
*   @{
*   @defgroup gwFileReturnStatusDefinitions Glasswall Return Status Definitions
*   @{
*
*   The document processing functions use the enumerations defined on these pages to describe the processing results. \n
*   \n
*   For the @ref gwFileProcessingFileToMemory functions only ::eGwFileStatus_Success,  ::eGwFileStatus_Error and ::eGwFileStatus_InternalError are used.
*   For the @ref gwFileProcessingFileToFile functions the negative values are utilised to report issues with file output (possibly in addition to file processing issues)
*   @attention Some of the @ref gwFileProcessingFileToFile functions' negative return values indicate documents have been successfully managed. It may be additional outputs that have
*   caused the error condition to be reported. Care should be taken to make the managed document available if possible.
*
**/

/** Enumerations report the following conditions */
typedef enum
{
    /** This value indicates the operation completed successfully. Any required Analysis or Protection was carried out and completed. */
    /** Any required output files were written. */
    eGwFileStatus_Success = 1,

    /** This value indicates that the document was non-conformant in some way, but any requested output files were written. */
    eGwFileStatus_Error = 0,

    /** This value indicates an uncategorised error */
    eGwFileStatus_InternalError = -9,

} eGwFileStatus;

/** @} */
/** @} */

#endif