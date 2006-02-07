/* $Cambridge: exim/src/src/lookups/pgsql.h,v 1.3 2006/02/07 11:19:01 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2006 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the pgsql lookup functions */

extern void *pgsql_open(uschar *, uschar **);
extern int   pgsql_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);
extern void  pgsql_tidy(void);
extern uschar *pgsql_quote(uschar *, uschar *);

/* End of lookups/pgsql.h */
