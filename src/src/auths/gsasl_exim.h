/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* Copyright (c) The Exim Maintainers 2019-2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Twitter Inc 2012 */

/* Interface to GNU SASL library for generic authentication. */

/* Authenticator-specific options. */

typedef struct {
  uschar *server_service;
  uschar *server_hostname;
  uschar *server_realm;
  uschar *server_mech;
  uschar *server_password;
  uschar *server_key;
  uschar *server_s_key;
  uschar *server_scram_iter;
  uschar *server_scram_salt;

  uschar *client_username;
  uschar *client_password;
  uschar *client_authz;
  uschar *client_spassword;

  BOOL    server_channelbinding;
  BOOL	  client_channelbinding;
} auth_gsasl_options_block;

/* Data for reading the authenticator-specific options. */

extern optionlist auth_gsasl_options[];
extern int auth_gsasl_options_count;

/* Defaults for the authenticator-specific options. */

extern auth_gsasl_options_block auth_gsasl_option_defaults;

/* The entry points for the mechanism */

extern void auth_gsasl_init(auth_instance *);
extern int auth_gsasl_server(auth_instance *, uschar *);
extern int auth_gsasl_client(auth_instance *, void *,
				int, uschar *, int);
extern void auth_gsasl_version_report(FILE *f);
extern void auth_gsasl_macros(void);

/* End of gsasl_exim.h */
