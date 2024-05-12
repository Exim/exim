/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This was in exim.h - but not all files needing it can include all of that. */
/* Needed by macros.h */
/* Some systems have PATH_MAX and some have MAX_PATH_LEN. */
#ifndef PATH_MAX
# ifdef MAX_PATH_LEN
#  define PATH_MAX MAX_PATH_LEN
# else
#  define PATH_MAX 4096
# endif
#endif

