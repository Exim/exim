/* $Cambridge: exim/src/src/dkim-exim.h,v 1.1 2007/09/28 12:21:57 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

/* Exim interface to DKIM results */

#define DKIM_EXIM_FAIL         -2     /* Message has a bad signature from that domain or identity. */
#define DKIM_EXIM_DEFER        -1     /* Message has an unverified signature from that domain */
#define DKIM_EXIM_UNVERIFIED    0     /* Message was not validated with the DK engine */
#define DKIM_EXIM_UNSIGNED      1     /* Message has no signature from that domain or identity */
#define DKIM_EXIM_GOOD          2     /* Message has good signature from that domain or identity */


#ifdef EXPERIMENTAL_DKIM
#include <dkim.h>

int     dkim_exim_verify_result(uschar *,uschar **,uschar **);

/* Internal prototypes */
int     dkim_receive_getc(void);
int     dkim_receive_ungetc(int);
void    dkim_exim_verify_init(void);
void    dkim_exim_verify_finish(void);
uschar *dkim_exim_sign(int, uschar *, uschar *, uschar *, uschar *, uschar *);
unsigned int dkim_status_wrap(int, uschar *);

#endif
