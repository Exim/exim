/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Header for the functions that are shared by the lookups */

extern int     lf_check_file(int, const uschar *, int, int,
		  const uid_t *, const gid_t *, const char *, uschar **);
extern gstring *lf_quote(uschar *, uschar *, int, gstring *);
extern int     lf_sqlperform(const uschar *, const uschar *, const uschar *,
		 const uschar *, uschar **,
                 uschar **, uint *, const uschar *,
		 int(*)(const uschar *, uschar *, uschar **,
                 uschar **, BOOL *, uint *, const uschar *));

/* End of lf_functions.h */
