/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "plaintext.h"


/* Options specific to the plaintext authentication mechanism. */

optionlist auth_plaintext_options[] = {
  { "client_ignore_invalid_base64", opt_bool,
      OPT_OFF(auth_plaintext_options_block, client_ignore_invalid_base64) },
  { "client_send",        opt_stringptr,
      OPT_OFF(auth_plaintext_options_block, client_send) },
  { "server_prompts",     opt_stringptr,
      OPT_OFF(auth_plaintext_options_block, server_prompts) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_plaintext_options_count =
  sizeof(auth_plaintext_options)/sizeof(optionlist);

/* Default private options block for the plaintext authentication method. */

auth_plaintext_options_block auth_plaintext_option_defaults = {
  NULL,              /* server_prompts */
  NULL,              /* client_send */
  FALSE              /* client_ignore_invalid_base64 */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_plaintext_init(auth_instance *ablock) {}
int auth_plaintext_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_plaintext_client(auth_instance *ablock, void * sx, int timeout,
    uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_plaintext_init(auth_instance *ablock)
{
auth_plaintext_options_block *ob =
  (auth_plaintext_options_block *)(ablock->options_block);
if (ablock->public_name == NULL) ablock->public_name = ablock->name;
if (ablock->server_condition != NULL) ablock->server = TRUE;
if (ob->client_send != NULL) ablock->client = TRUE;
}



/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_plaintext_server(auth_instance * ablock, uschar * data)
{
auth_plaintext_options_block * ob =
  (auth_plaintext_options_block *)(ablock->options_block);
const uschar * prompts = ob->server_prompts;
uschar * s;
int number = 1;
int rc;
int sep = 0;

/* Expand a non-empty list of prompt strings */

if (prompts)
  if (!(prompts = expand_cstring(prompts)))
    {
    auth_defer_msg = expand_string_message;
    return DEFER;
    }

/* If data was supplied on the AUTH command, decode it, and split it up into
multiple items at binary zeros. The strings are put into $auth1, $auth2, etc,
up to a maximum. To retain backwards compatibility, they are also put int $1,
$2, etc. If the data consists of the string "=" it indicates a single, empty
string. */

if (*data)
  if ((rc = auth_read_input(data)) != OK)
    return rc;

/* Now go through the list of prompt strings. Skip over any whose data has
already been provided as part of the AUTH command. For the rest, send them
out as prompts, and get a data item back. If the data item is "*", abandon the
authentication attempt. Otherwise, split it into items as above. */

while (  (s = string_nextinlist(&prompts, &sep, big_buffer, big_buffer_size))
      && expand_nmax < EXPAND_MAXN)
  if (number++ > expand_nmax)
    if ((rc = auth_prompt(CUS s)) != OK)
      return rc;

/* We now have a number of items of data in $auth1, $auth2, etc (and also, for
compatibility, in $1, $2, etc). Authentication and authorization are handled
together for this authenticator by expanding the server_condition option. Note
that ablock->server_condition is always non-NULL because that's what configures
this authenticator as a server. */

return auth_check_serv_cond(ablock);
}



/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_plaintext_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* smtp connextion */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* buffer for reading response */
  int buffsize)                          /* size of buffer */
{
auth_plaintext_options_block *ob =
  (auth_plaintext_options_block *)(ablock->options_block);
const uschar * text = ob->client_send;
const uschar * s;
int sep = 0;
int auth_var_idx = 0, rc;
int flags = AUTH_ITEM_FIRST;

if (ob->client_ignore_invalid_base64)
  flags |= AUTH_ITEM_IGN64;

/* The text is broken up into a number of different data items, which are
sent one by one. The first one is sent with the AUTH command; the remainder are
sent in response to subsequent prompts. Each is expanded before being sent. */

while ((s = string_nextinlist(&text, &sep, NULL, 0)))
  {
  if (!text)
    flags |= AUTH_ITEM_LAST;

  if ((rc = auth_client_item(sx, ablock, &s, flags, timeout, buffer, buffsize))
       != DEFER)
    return rc;

  flags &= ~AUTH_ITEM_FIRST;

  if (auth_var_idx < AUTH_VARS)
    auth_vars[auth_var_idx++] = string_copy(s);
  }

/* Control should never actually get here. */

return FAIL;
}

#endif   /*!MACRO_PREDEF*/
/* End of plaintext.c */
