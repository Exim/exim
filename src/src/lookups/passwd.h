/* $Cambridge: exim/src/src/lookups/passwd.h,v 1.2 2005/01/04 10:00:44 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the passwd lookup */

extern void *passwd_open(uschar *, uschar **);
extern int   passwd_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);

/* End of lookups/passwd.h */
