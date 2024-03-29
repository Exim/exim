/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003 - 2015 */
/* Copyright (c) The Exim Maintainers 2021 */
/* License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* spam defines */

#ifdef WITH_CONTENT_SCAN

/* timeout for reading and writing spamd */
#define SPAMD_TIMEOUT 120

/* maximum length of the spam bar, please update the
 * spec, the max length is mentioned there */
#define MAX_SPAM_BAR_CHARS 50

/* SHUT_WR seems to be undefined on Unixware ? */
#ifndef SHUT_WR
# define SHUT_WR 1
#endif

/* Defaults */
#define SPAMD_WEIGHT 1
#define SPAMD_PRIORITY 1

typedef struct spamd_address_container
{
  uschar * hostspec;
  int is_rspamd:1;
  int is_failed:1;
  unsigned int weight;
  unsigned int timeout;
  unsigned int retry;
  unsigned int priority;
} spamd_address_container;

#endif
