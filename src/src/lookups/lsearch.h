/* $Cambridge: exim/src/src/lookups/lsearch.h,v 1.5 2009/11/16 19:50:38 nm4 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the lsearch and wildlsearch lookups */

extern void *lsearch_open(uschar *, uschar **);
extern BOOL  lsearch_check(void *, uschar *, int, uid_t *, gid_t *, uschar **);
extern int   lsearch_find(void *, uschar *, uschar *, int, uschar **,
               uschar **, BOOL *);
extern void  lsearch_close(void *);

extern int   wildlsearch_find(void *, uschar *, uschar *, int, uschar **,
               uschar **, BOOL *);
extern int   nwildlsearch_find(void *, uschar *, uschar *, int, uschar **,
               uschar **, BOOL *);
extern int   iplsearch_find(void *, uschar *, uschar *, int, uschar **,
               uschar **, BOOL *);

/* End of lookups/lsearch.h */
