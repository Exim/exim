/* $Cambridge: exim/src/src/spam.h,v 1.1.2.1 2004/11/26 09:13:34 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* This file is part of the exiscan-acl content scanner
patch. It is NOT part of the standard exim distribution. */

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* spam defines */

/* timeout for reading from spamd */
#define SPAMD_READ_TIMEOUT 3600

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



