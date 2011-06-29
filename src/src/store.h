/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for Exim's memory allocation functions */

#ifndef STORE_H
#define STORE_H

/* Define symbols for identifying the store pools. */

enum { POOL_MAIN, POOL_PERM, POOL_SEARCH };

/* This variable (the one for the current pool) is set by store_get() to its
yield, and by store_reset() to NULL. This allows string_cat() to optimize its
store handling. */

extern void *store_last_get[3];

/* This variable contains the current store pool number. */

extern int store_pool;

/* Macros for calling the memory allocation routines with
tracing information for debugging. */

#define store_extend(addr,old,new) \
  store_extend_3(addr, old, new, __FILE__, __LINE__)

#define store_free(addr)     store_free_3(addr, __FILE__, __LINE__)
#define store_get(size)      store_get_3(size, __FILE__, __LINE__)
#define store_get_perm(size) store_get_perm_3(size, __FILE__, __LINE__)
#define store_malloc(size)   store_malloc_3(size, __FILE__, __LINE__)
#define store_release(addr)  store_release_3(addr, __FILE__, __LINE__)
#define store_reset(addr)    store_reset_3(addr, __FILE__, __LINE__)


/* The real functions */

extern BOOL    store_extend_3(void *, int, int, const char *, int);  /* The */
extern void    store_free_3(void *, const char *, int);     /* value of the */
extern void   *store_get_3(int, const char *, int);         /* 2nd arg is   */
extern void   *store_get_perm_3(int, const char *, int);    /* __FILE__ in  */
extern void   *store_malloc_3(int, const char *, int);      /* every call,  */
extern void    store_release_3(void *, const char *, int);  /* so give its  */
extern void    store_reset_3(void *, const char *, int);    /* correct type */

#endif  /* STORE_H */

/* End of store.h */
