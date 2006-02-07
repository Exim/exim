/* $Cambridge: exim/src/src/lookups/ldap.h,v 1.3 2006/02/07 11:19:01 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2006 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the ldap lookups */

extern void   *eldap_open(uschar *, uschar **);
extern int     eldap_find(void *, uschar *, uschar *, int, uschar **, uschar **,
                 BOOL *);
extern int     eldapauth_find(void *, uschar *, uschar *, int, uschar **,
                 uschar **, BOOL *);
extern int     eldapdn_find(void *, uschar *, uschar *, int, uschar **,
                 uschar **, BOOL *);
extern int     eldapm_find(void *, uschar *, uschar *, int, uschar **,
                 uschar **, BOOL *);
extern void    eldap_tidy(void);
extern uschar *eldap_quote(uschar *, uschar *);

/* End of lookups/ldap.h */
