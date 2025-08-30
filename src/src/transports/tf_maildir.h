/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2021 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Header file for the functions that are used to support the use of
maildirsize files for quota handling in maildir directories. */

extern off_t  maildir_compute_size(const uschar *, int *, time_t *,
		const pcre2_code *, const pcre2_code *, BOOL);
extern BOOL   maildir_ensure_directories(const uschar *, address_item *, BOOL,
		int, const uschar *);
extern int    maildir_ensure_sizefile(uschar *,
                appendfile_transport_options_block *, const pcre2_code *,
                const pcre2_code *, off_t *, int *);
extern void   maildir_record_length(int, int);

/* End of tf_maildir.h */
