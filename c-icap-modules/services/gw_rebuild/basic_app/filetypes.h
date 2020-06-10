#ifndef FILETYPES_H
#define FILETYPES_H

typedef enum
{
    // The default when we don't know or can't determine the file type
    ft_unknown,

    // Not related to filetypes, but these are required since they give information when something goes wrong
    ft_fileIssues,
    ft_bufferIssues,
    ft_internalIssues,
    ft_licenseExpired,
    ft_passwordProtectedOpcFile,

    // The file types that we support
    ft_pdf = 0x10,
    ft_doc,
    ft_docx,
    ft_ppt,
    ft_pptx,
    ft_xls,
    ft_xlsx,
    ft_png,
    ft_jpeg,
    ft_gif,
    ft_emf,
    ft_wmf,
    ft_rtf,
    ft_bmp
} ft_t;

#endif /* FILETYPES_H */
