/* $Cambridge: exim/src/src/spam.h,v 1.3 2005/04/27 10:00:18 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* spam defines */

#ifdef WITH_CONTENT_SCAN

/* timeout for reading and writing spamd */
#define SPAMD_TIMEOUT 120

/* maximum length of the spam bar */
#define MAX_SPAM_BAR_CHARS 50

/* SHUT_WR seems to be undefined on Unixware ? */
#ifndef SHUT_WR
#define SHUT_WR 1
#endif

typedef struct spamd_address_container {
  uschar tcp_addr[24];
  unsigned int tcp_port;
} spamd_address_container;

#endif
