/* $Cambridge: exim/src/src/lookups/whoson.h,v 1.1 2004/10/07 13:10:01 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2004 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the whoson lookup */

extern void *whoson_open(uschar *, uschar **);
extern int   whoson_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);

/* End of lookups/whoson.h */
