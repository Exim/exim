/* $Cambridge: exim/src/src/auths/plaintext.h,v 1.6 2007/01/08 10:50:19 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *server_prompts;
  uschar *client_send;
  BOOL    client_ignore_invalid_base64;
} auth_plaintext_options_block;

/* Data for reading the private options. */

extern optionlist auth_plaintext_options[];
extern int auth_plaintext_options_count;

/* Block containing default values. */

extern auth_plaintext_options_block auth_plaintext_option_defaults;

/* The entry points for the mechanism */

extern void auth_plaintext_init(auth_instance *);
extern int auth_plaintext_server(auth_instance *, uschar *);
extern int auth_plaintext_client(auth_instance *, smtp_inblock *,
                                 smtp_outblock *, int, uschar *, int);

/* End of plaintext.h */
