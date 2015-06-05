/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge, 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

uschar *dkim_exim_sign(int, uschar *, const uschar *, uschar *, uschar *, uschar *);
void    dkim_exim_verify_init(void);
void    dkim_exim_verify_feed(uschar *, int);
void    dkim_exim_verify_finish(void);
void    dkim_exim_acl_setup(uschar *);
uschar *dkim_exim_expand_query(int);
uschar *dkim_exim_expand_defaults(int);

#define DKIM_ALGO               1
#define DKIM_BODYLENGTH         2
#define DKIM_CANON_BODY         3
#define DKIM_CANON_HEADERS      4
#define DKIM_COPIEDHEADERS      5
#define DKIM_CREATED            6
#define DKIM_EXPIRES            7
#define DKIM_HEADERNAMES        8
#define DKIM_IDENTITY           9
#define DKIM_KEY_GRANULARITY   10
#define DKIM_KEY_SRVTYPE       11
#define DKIM_KEY_NOTES         12
#define DKIM_KEY_TESTING       13
#define DKIM_NOSUBDOMAINS      14
#define DKIM_VERIFY_STATUS     15
#define DKIM_VERIFY_REASON     16
