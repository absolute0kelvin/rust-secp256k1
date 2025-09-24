#ifndef SECP_ALLOC_REMAP_H
#define SECP_ALLOC_REMAP_H

/* Force remap of malloc family to dlmalloc for all C TUs compiled in this crate */
#define malloc  dlmalloc
#define free    dlfree
#define realloc dlrealloc
#define calloc  dlcalloc

#endif /* SECP_ALLOC_REMAP_H */


