/* $Cambridge: exim/src/src/lookups/lf_functions.h,v 1.1 2004/10/07 13:10:01 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2004 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the functions that are shared by the lookups */

extern int     lf_check_file(int, uschar *, int, int, uid_t *, gid_t *, char *,
                 uschar **);
extern uschar *lf_quote(uschar *, uschar *, int, uschar *, int *, int *);

/* End of lf_functions.h */
