#ifndef PAGAN_PAGAN_HASH 
#define PAGAN_PAGAN_HASH_H 1

#include <common/pagan/pagan.h>

#define uthash_malloc(size)  pagan_malloc(size)
#define uthash_free(ptr, sz) pagan_free(ptr)
#define uthash_fatal(msg)    pagan_fatal()

#include <common/ut/uthash.h>

#endif
