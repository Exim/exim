/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* API definitions for the dmarc module */


/* Function table entry numbers */

#define	DMARC_PROCESS		0
#define DMARC_EXPAND_QUERY	1
#define DMARC_AUTHRES		2
#define DMARC_STORE_DATA	3
