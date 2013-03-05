#ifndef _COMMON_TYPES_H_
#define _COMMON_TYPES_H_
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include "os_defs.h"
typedef struct {
    /** Six octet holding the MAC address */
    uint8_t octet[6];
} cparser_macaddr_t;
typedef void * TIMER_ID;

#define UNUSED_PARAM  __attribute__((unused))
#endif
