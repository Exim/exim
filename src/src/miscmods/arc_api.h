/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* API definitions for the arcmodule */


/* Function table entry numbers */

#define	ARC_VERIFY		0
#define ARC_HEADER_FEED		1
#define ARC_STATE_IS_PASS	2
#define ARC_SIGN_INIT		3
#define ARC_SIGN		4
#define ARC_ARCSET_INFO		5
