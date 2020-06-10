#include "gwfiletypes.h"

/* cli_ft: convert Glasswall ft_t into CLI's mapping */
int cli_ft(int ft)
{
    static const MAX_FT_T = 261;  /* WARNING: This must be maintained if ft_t changes */
    static const EXT_LIB_RANGE_START = 0x100;
    
    /* 216 is EXT_LIB_RANGE_START - 40; 40 is the index of FT_ZIP in gwFileTypeResults[] */
    static const MAP_ADJUST = 216;

    if (ft >= 0 && ft <= MAX_FILETYPE) return ft;
    if (ft >= EXT_LIB_RANGE_START && ft <= MAX_FT_T) return ft - MAP_ADJUST;
    return 0;
}