/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 - 2025 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* API definitions for the spf module */

#ifdef EXPERIMENTAL_SPF_PERL

enum spf_result_code {
        SPF_RESULT_INVALID = 0,
        SPF_RESULT_NEUTRAL,
        SPF_RESULT_PASS,
        SPF_RESULT_FAIL,
        SPF_RESULT_SOFTFAIL,

        SPF_RESULT_NONE,
        SPF_RESULT_TEMPERROR,
        SPF_RESULT_PERMERROR
};

#else
# include <spf2/spf_response.h>
#endif

/* Function table entry numbers */

#define	SPF_PROCESS		0
#define SPF_GET_RESULTS		1
#define SPF_OPEN		2
#define SPF_CLOSE		3
#define SPF_FIND		4
