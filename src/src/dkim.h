/* $Cambridge: exim/src/src/dkim.h,v 1.1.2.3 2009/04/09 13:57:21 tom Exp $ */

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

int dkim_exim_verify_init(void);
int dkim_exim_verify_feed(uschar *, int);
int dkim_exim_verify_finish(void);
int dkim_exim_verify_result(uschar *,
                            uschar **,
                            uschar **);
