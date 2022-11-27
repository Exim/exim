/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2022 */
/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Copyright (c) Twitter Inc 2012
   Author: Phil Pennock <pdp@exim.org> */
/* Copyright (c) Phil Pennock 2012 */

/* Interface to Heimdal library for GSSAPI authentication. */

/* Authenticator-specific options. */

typedef struct {
  uschar *server_hostname;
  uschar *server_keytab;
  uschar *server_service;
} auth_heimdal_gssapi_options_block;

/* Data for reading the authenticator-specific options. */

extern optionlist auth_heimdal_gssapi_options[];
extern int auth_heimdal_gssapi_options_count;

/* Defaults for the authenticator-specific options. */

extern auth_heimdal_gssapi_options_block auth_heimdal_gssapi_option_defaults;

/* The entry points for the mechanism */

extern void auth_heimdal_gssapi_init(auth_instance *);
extern int auth_heimdal_gssapi_server(auth_instance *, uschar *);
extern int auth_heimdal_gssapi_client(auth_instance *, void *, int, uschar *, int);
extern void auth_heimdal_gssapi_version_report(BOOL);

/* End of heimdal_gssapi.h */
