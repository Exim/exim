/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the functions that are shared by the lookups */

extern int     lf_check_file(int, uschar *, int, int, uid_t *, gid_t *,
                 const char *, uschar **);
extern uschar *lf_quote(uschar *, uschar *, int, uschar *, int *, int *);
extern int     lf_sqlperform(const uschar *, const uschar *, const uschar *,
		 const uschar *, uschar **,
                 uschar **, BOOL *, int(*)(const uschar *, uschar *, uschar **,
                 uschar **, BOOL *, BOOL *));

/* End of lf_functions.h */
