/**
 * @file util.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Some helpful utilities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <string.h>
#include "libsftp/libssh.h"
#ifdef LINUX
    #include <arpa/inet.h>
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/** Free memory space */
#define SAFE_FREE(x)       \
    do {                   \
        if ((x) != NULL) { \
            free(x);       \
            x = NULL;      \
        }                  \
    } while (0)

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x)                                        \
    do {                                                       \
        if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); \
    } while (0)

/** Zero memory */
#define ZERO(p, n) memset((char *)(p), 0, n)

/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define VA_APPLY_VARIADIC_MACRO(macro, tuple) macro tuple

#define __VA_NARG__(...) (__VA_NARG_(__VA_ARGS__, __RSEQ_N()))
#define __VA_NARG_(...) VA_APPLY_VARIADIC_MACRO(__VA_ARG_N, (__VA_ARGS__))
#define __VA_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13,     \
                   _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, \
                   _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, \
                   _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, \
                   _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, \
                   _62, _63, N, ...)                                           \
    N
#define __RSEQ_N()                                                          \
    63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, \
        45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, \
        28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, \
        11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#ifdef LINUX
#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifdef __BIG_ENDIAN__
#define ntohll(x) (x)
#else
#define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
#endif

void explicit_bzero(void *s, size_t n);

char *ssh_get_local_username(void); 
char *ssh_get_home_dir(void);

void ssh_log_hexdump(const char *descr, const unsigned char *what, size_t len);

void ssh_print_ctrl_filtered_string(ssh_string str);

#endif /* UTIL_H */