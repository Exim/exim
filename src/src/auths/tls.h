/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2025 */
/* Copyright (c) Jeremy Harris 2015 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Private structure for the private options. */

typedef struct {
  uschar * server_param1;
  uschar * server_param2;
  uschar * server_param3;
} auth_tls_options_block;

/* Data for reading the private options. */

extern optionlist auth_tls_options[];
extern int auth_tls_options_count;

/* Block containing default values. */

extern auth_tls_options_block auth_tls_option_defaults;

/* The entry points for the mechanism */

extern void auth_tls_init(driver_instance *);
extern int auth_tls_server(auth_instance *, uschar *);

/* End of tls.h */
