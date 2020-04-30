/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for Exim's memory allocation functions */

#ifndef STORE_H
#define STORE_H

/* Define symbols for identifying the store pools. */

enum { POOL_MAIN,       POOL_PERM,       POOL_SEARCH,
       POOL_TAINT_BASE,
       POOL_TAINT_MAIN = POOL_TAINT_BASE, POOL_TAINT_PERM, POOL_TAINT_SEARCH };

/* This variable (the one for the current pool) is set by store_get() to its
yield, and by store_reset() to NULL. This allows string_cat() to optimize its
store handling. */

extern void *store_last_get[6];

/* This variable contains the current store pool number. */

extern int store_pool;

/* Macros for calling the memory allocation routines with
tracing information for debugging. */

#define store_extend(addr, tainted, old, new) \
  store_extend_3(addr, tainted, old, new, __FUNCTION__, __LINE__)

#define store_free(addr) \
	store_free_3(addr, __FUNCTION__, __LINE__)
/* store_get & store_get_perm are in local_scan.h */
#define store_malloc(size) \
	store_malloc_3(size, __FUNCTION__, __LINE__)
#define store_mark(void) \
	store_mark_3(__FUNCTION__, __LINE__)
#define store_newblock(addr, tainted, newsize, datalen) \
	store_newblock_3(addr, tainted, newsize, datalen, __FUNCTION__, __LINE__)
#define store_release_above(addr) \
	store_release_above_3(addr, __FUNCTION__, __LINE__)
#define store_reset(mark) \
	store_reset_3(mark, store_pool, __FUNCTION__, __LINE__)


/* The real functions */
typedef void ** rmark;

extern BOOL    store_extend_3(void *, BOOL, int, int, const char *, int);
extern void    store_free_3(void *, const char *, int);
/* store_get_3 & store_get_perm_3 are in local_scan.h */
extern void   *store_malloc_3(int, const char *, int)		ALLOC ALLOC_SIZE(1) WARN_UNUSED_RESULT;
extern rmark   store_mark_3(const char *, int);
extern void   *store_newblock_3(void *, BOOL, int, int, const char *, int);
extern void    store_release_above_3(void *, const char *, int);
extern rmark   store_reset_3(rmark, int, const char *, int);

#endif  /* STORE_H */

/* End of store.h */
