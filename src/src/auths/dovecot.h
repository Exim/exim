/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainters 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *	server_socket;
  BOOL		server_tls;
} auth_dovecot_options_block;

/* Data for reading the private options. */

extern optionlist auth_dovecot_options[];
extern int auth_dovecot_options_count;

/* Block containing default values. */

extern auth_dovecot_options_block auth_dovecot_option_defaults;

/* The entry points for the mechanism */

extern void auth_dovecot_init(auth_instance *);
extern int auth_dovecot_server(auth_instance *, uschar *);

/* End of dovecot.h */
