/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2021 - 2023 */
/* Copyright (c) Jeremy Harris 2017 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Global functions */

extern void spf(uschar *, int, const uschar *, ...);
extern void builtin_macro_create(const uschar *);
extern void builtin_macro_create_var(const uschar *, const uschar *);
extern void options_from_list(optionlist *, unsigned, const uschar *, uschar *);

extern void features_acl(void);
extern void features_malware(void);
extern void features_crypto(void);
extern void options_main(void);
extern void options_routers(void);
extern void options_transports(void);
extern void options_auths(void);
extern void options_logging(void);
extern void expansions(void);
extern void params_dkim(void);
#ifndef DISABLE_TLS
extern void options_tls(void);
#endif

