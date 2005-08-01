/* $Cambridge: exim/src/src/lookups/sqlite.h,v 1.1 2005/08/01 13:20:28 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the sqlite lookup */

extern void   *sqlite_open(uschar *, uschar **);
extern int     sqlite_find(void *, uschar *, uschar *, int, uschar **,
                 uschar **, BOOL *);
extern void    sqlite_close(void *);
extern uschar *sqlite_quote(uschar *, uschar *);

/* End of lookups/sqlite.h */
