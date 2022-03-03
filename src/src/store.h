/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2020 - 2021 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for Exim's memory allocation functions */

#ifndef STORE_H
#define STORE_H

/* Define symbols for identifying the store pools. */

enum { POOL_MAIN,
       POOL_PERM,
       POOL_CONFIG,
       POOL_SEARCH,
       POOL_MESSAGE,

       POOL_TAINT_BASE,

       POOL_TAINT_MAIN = POOL_TAINT_BASE,
       POOL_TAINT_PERM,
       POOL_TAINT_CONFIG,
       POOL_TAINT_SEARCH,
       POOL_TAINT_MESSAGE,

       N_PAIRED_POOLS
};

/* This variable (the one for the current pool) is set by store_get() to its
yield, and by store_reset() to NULL. This allows string_cat() to optimize its
store handling. */

extern void * store_last_get[];

/* This variable contains the current store pool number. */

extern int store_pool;

/* Macros for calling the memory allocation routines with
tracing information for debugging. */

#define store_extend(addr, old, new) \
  store_extend_3(addr, old, new, __FUNCTION__, __LINE__)

#define store_free(addr) \
	store_free_3(addr, __FUNCTION__, __LINE__)
/* store_get & store_get_perm are in local_scan.h */
#define store_get_quoted(size, proto_mem, quoter) \
	store_get_quoted_3((size), (proto_mem), (quoter), __FUNCTION__, __LINE__)
#define store_malloc(size) \
	store_malloc_3(size, __FUNCTION__, __LINE__)
#define store_mark(void) \
	store_mark_3(__FUNCTION__, __LINE__)
#define store_newblock(oldblock, newsize, datalen) \
	store_newblock_3(oldblock, newsize, datalen, __FUNCTION__, __LINE__)
#define store_release_above(addr) \
	store_release_above_3(addr, __FUNCTION__, __LINE__)
#define store_reset(mark) \
	store_reset_3(mark, __FUNCTION__, __LINE__)


/* The real functions */
typedef void ** rmark;

extern BOOL    store_extend_3(void *, int, int, const char *, int);
extern void    store_free_3(void *, const char *, int);
/* store_get_3 & store_get_perm_3 are in local_scan.h */
extern void *  store_get_quoted_3(int, const void *, unsigned, const char *, int);
extern void *  store_malloc_3(size_t, const char *, int)		ALLOC ALLOC_SIZE(1) WARN_UNUSED_RESULT;
extern rmark   store_mark_3(const char *, int);
extern void *  store_newblock_3(void *, int, int, const char *, int);
extern void    store_release_above_3(void *, const char *, int);
extern rmark   store_reset_3(rmark, const char *, int);

#define GET_UNTAINTED	(const void *)0
#define GET_TAINTED	(const void *)1

extern int	quoter_for_address(const void *);
extern BOOL	is_quoted_like(const void *, unsigned);
extern BOOL	is_real_quoter(int);
extern void	debug_print_taint(const void * p);

#endif  /* STORE_H */

/* End of store.h */
