/* $Cambridge: exim/src/src/lookups/dkim.h,v 1.1 2007/09/28 12:21:57 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the DKIM lookup */

extern void *dkim_open(uschar *, uschar **);
extern int   dkim_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);

/* End of lookups/dkim.h */
