#ifndef GWFILETYPES_H
#define GWFILETYPES_H

#define FT_UNKNOWN "Unknown"
#define FT_FILE_ISSUE "File issues"
#define FT_BUFFER_ISSUE "Buffer issues"
#define FT_INTERNAL_ISSUE "Internal issues"
#define FT_LICENSE_EXPIRED "License expired"
#define FT_PASSWORD_PROTECTED "Password protected OPC file"
#define FT_NULL_POINTER "Null pointer argument"
#define FT_UNDEFINED "Undefined"

#define FT_PDF "pdf"
#define FT_DOC "doc"
#define FT_DOCX "docx"
#define FT_PPT "ppt"
#define FT_PPTX "pptx"
#define FT_XLS "xls"
#define FT_XLSX "xlsx"
#define FT_PNG "png"
#define FT_JPEG "jpeg"
#define FT_GIF "gif"
#define FT_EMF "emf"
#define FT_WMF "wmf"
#define FT_RTF "rtf"
#define FT_BMP "bmp"
#define FT_TIFF "tiff"
#define FT_PE "pe"
#define FT_MACHO "macho"
#define FT_ELF "elf"
#define FT_MP4 "mp4"
#define FT_MP3 "mp3"
#define FT_MP2 "mp2"
#define FT_WAV "wav"
#define FT_MPG "mpg"
#define FT_COFF "pe"   /* treat COFF as PE */
#define FT_ZIP "zip"
#define FT_GZIP "gzip"
#define FT_BZIP2 "bzip2"
#define FT_SEVENZIP "sevenzip"
#define FT_RAR "rar"
#define FT_TAR "tar"

static const char *gwFileTypeResults[] = {
    FT_UNKNOWN,               /* 0 */
    FT_FILE_ISSUE,
    FT_BUFFER_ISSUE,
    FT_INTERNAL_ISSUE,
    FT_LICENSE_EXPIRED,
    FT_PASSWORD_PROTECTED,
    FT_NULL_POINTER,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_UNDEFINED,
    FT_PDF,                   /* 16 (0x10) */
    FT_DOC,
    FT_DOCX,
    FT_PPT,
    FT_PPTX,
    FT_XLS,
    FT_XLSX,
    FT_PNG,
    FT_JPEG,
    FT_GIF,
    FT_EMF,
    FT_WMF,
    FT_RTF,
    FT_BMP,
    FT_TIFF,
    FT_PE,
    FT_MACHO,
    FT_ELF,
    FT_MP4,
    FT_MP3,
    FT_MP2,
    FT_WAV,
    FT_MPG,
    FT_COFF,
    FT_ZIP,                   /* 256 (0x100) */
    FT_GZIP,
    FT_BZIP2,
    FT_SEVENZIP,
    FT_RAR,
    FT_TAR 
};

#define   NELEMENTS(a)   (sizeof(a) / sizeof(a[0]))

#define   FIRST_KNOWN_FILETYPE   0x10 
#define   MAX_FILETYPE   (NELEMENTS(gwFileTypeResults)-1)

int cli_ft(int ft);


#endif