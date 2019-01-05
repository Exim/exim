/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2019 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar * server_param2;
  uschar * server_param3;

  uschar * client_send;
} auth_external_options_block;

/* Data for reading the private options. */

extern optionlist auth_external_options[];
extern int auth_external_options_count;

/* Block containing default values. */

extern auth_external_options_block auth_external_option_defaults;

/* The entry points for the mechanism */

extern void auth_external_init(auth_instance *);
extern int auth_external_server(auth_instance *, uschar *);
extern int auth_external_client(auth_instance *, void *, int, uschar *, int);

/* End of external.h */
