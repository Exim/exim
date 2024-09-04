/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* API definitions for the dkim module */


/* Function table entry numbers */

#define DKIM_VERIFY_FEED	0
#define DKIM_VERIFY_PAUSE	1
#define DKIM_VERIFY_FINISH	2
#define DKIM_ACL_ENTRY		3
#define DKIM_VERIFY_LOG_ALL	4
#define DKIM_VDOM_FIRSTPASS	5
#define DKIM_SIGNER_ISINLIST	6
#define DKIM_STATUS_LISTMATCH	7
#define DKIM_SETVAR		8
#define DKIM_EXPAND_QUERY	9
#define DKIM_TRANSPORT_INIT	10
#define DKIM_TRANSPORT_WRITE	11

#define DKIM_SIGS_LIST		12

#define DKIM_HASHNAME_TO_TYPE	13
#define DKIM_HASHTYPE_TO_METHOD	14
#define DKIM_HASHNAME_TO_METHOD	15
#define DKIM_SET_BODYHASH	16
#define DKIM_DNS_PUBKEY		17
#define DKIM_SIG_VERIFY		18
#define DKIM_HEADER_RELAX	19
#define DKIM_SIGN_DATA		20
