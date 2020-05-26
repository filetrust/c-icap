#ifndef GWFILETYPES_H
#define GWFILETYPES_H
#include <wchar.h>

#define FT_UNKNOWN L"Unknown"
#define FT_FILE_ISSUE L"File issues"
#define FT_BUFFER_ISSUE L"Buffer issues"
#define FT_INTERNAL_ISSUE L"Internal issues"
#define FT_LICENSE_EXPIRED L"License expired"
#define FT_PASSWORD_PROTECTED L"Password protected OPC file"
#define FT_NULL_POINTER L"Null pointer argument"
#define FT_UNDEFINED L"Undefined"

#define FT_PDF L"pdf"
#define FT_DOC L"doc"
#define FT_DOCX L"docx"
#define FT_PPT L"ppt"
#define FT_PPTX L"pptx"
#define FT_XLS L"xls"
#define FT_XLSX L"xlsx"
#define FT_PNG L"png"
#define FT_JPEG L"jpeg"
#define FT_GIF L"gif"
#define FT_EMF L"emf"
#define FT_WMF L"wmf"
#define FT_RTF L"rtf"
#define FT_BMP L"bmp"
#define FT_TIFF L"tiff"
#define FT_PE L"pe"
#define FT_MACHO L"macho"
#define FT_ELF L"elf"
#define FT_MP4 L"mp4"
#define FT_MP3 L"mp3"
#define FT_MP2 L"mp2"
#define FT_WAV L"wav"
#define FT_MPG L"mpg"
#define FT_COFF L"pe"   /* treat COFF as PE */
#define FT_ZIP L"zip"
#define FT_GZIP L"gzip"
#define FT_BZIP2 L"bzip2"
#define FT_SEVENZIP L"sevenzip"
#define FT_RAR L"rar"
#define FT_TAR L"tar"

static const wchar_t *gwFileTypeResults[] = {
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