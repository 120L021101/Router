#include <stdlib.h>

#ifndef ERR_H
#define ERR_H

#define IFERR_REPORT_AND_EXIT(OBJ, MSG) do { \
    if (OBJ == NULL) { \
        fprintf(stderr, MSG); \
        exit(0); \
    } \
} while (0)

#define ERR_REPORT_AND_EXIT(OBJ, MSG) do { \
    fprintf(stderr, MSG); \
    exit(0); \
} while (0)

#define TESTERR_REPORT_AND_EXIT(COND, MSG) do { \
    if (COND) { \
        fprintf(stderr, MSG); \
        exit(0); \
    } \
} while (0)


#endif