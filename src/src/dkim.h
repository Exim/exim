/* $Cambridge: exim/src/src/dkim.h,v 1.1.2.1 2009/02/24 15:57:55 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 2009 */
/* See the file NOTICE for conditions of use and distribution. */

uschar *dkim_exim_sign(int ,
                       uschar *,
                       uschar *,
                       uschar *,
                       uschar *,
                       uschar *);

