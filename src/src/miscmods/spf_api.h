/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* API definitions for the spfmodule */


/* Function table entry numbers */

#define	SPF_PROCESS		0
#define SPF_AUTHRES		1
#define SPF_GET_RESPONSE	2
#define SPF_OPEN		3
#define SPF_CLOSE		4
#define SPF_FIND		5
