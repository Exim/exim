/* $Cambridge: exim/src/src/lookups/nis.h,v 1.4 2007/01/08 10:50:19 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the nis and nis0 lookups */

extern void *nis_open(uschar *, uschar **);
extern int   nis_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);
extern int   nis0_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);

/* End of lookups/nis.h */
