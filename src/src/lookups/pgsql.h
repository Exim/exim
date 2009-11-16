/* $Cambridge: exim/src/src/lookups/pgsql.h,v 1.5 2009/11/16 19:50:38 nm4 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the pgsql lookup functions */

extern void *pgsql_open(uschar *, uschar **);
extern int   pgsql_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);
extern void  pgsql_tidy(void);
extern uschar *pgsql_quote(uschar *, uschar *);

/* End of lookups/pgsql.h */
