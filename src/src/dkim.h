/* $Cambridge: exim/src/src/dkim.h,v 1.1.2.4 2009/05/20 14:30:14 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 2009 */
/* See the file NOTICE for conditions of use and distribution. */

uschar *dkim_exim_sign(int,
                       uschar *,
                       uschar *,
                       uschar *,
                       uschar *,
                       uschar *);

void dkim_exim_verify_init(void);
void dkim_exim_verify_feed(uschar *, int);
void dkim_exim_verify_finish(void);
void dkim_exim_verify_result(uschar *,
                             uschar **,
                             uschar **);
