#ifndef SECP_ALLOC_REMAP_H
#define SECP_ALLOC_REMAP_H

/* Force remap of malloc family to dl-prefixed variants provided by dlmalloc.
 * USE_DL_PREFIX is defined in build.rs so these symbols are available.
 */
#define malloc  dlmalloc
#define free    dlfree
#define realloc dlrealloc
#define calloc  dlcalloc

#include <stddef.h>
void* dlmalloc(size_t size);
void dlfree(void* ptr);
void* dlcalloc(size_t nmemb, size_t size);
void* dlrealloc(void* ptr, size_t size);
#endif /* SECP_ALLOC_REMAP_H */


