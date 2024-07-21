/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2022 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2021 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DBFUNCTIONS_H
#define DBFUNCTIONS_H

/* Functions for reading/writing exim database files */

void     dbfn_close(open_db *);
void     dbfn_close_multi(open_db *);
int      dbfn_delete(open_db *, const uschar *);
open_db *dbfn_open(const uschar *, int, open_db *, BOOL, BOOL);
open_db * dbfn_open_path(const uschar *, open_db *);
open_db *dbfn_open_multi(const uschar *, int, open_db *);
void    *dbfn_read_klen(open_db *, const uschar *, int, int *);
void    *dbfn_read_with_length(open_db *, const uschar *, int *);
void    *dbfn_read_enforce_length(open_db *, const uschar *, size_t);
uschar  *dbfn_scan(open_db *, BOOL, EXIM_CURSOR **);
int      dbfn_write(open_db *, const uschar *, void *, int);
BOOL	 dbfn_transaction_start(open_db *);
void	 dbfn_transaction_commit(open_db *);

/* Macro for the common call to read without wanting to know the length. */

#define  dbfn_read(a, b) dbfn_read_with_length(a, b, NULL)

#endif
/* End of dbfunctions.h */
