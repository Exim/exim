/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2023 - 2024 */
/* Copyright (c) Jeremy Harris 2019-2020 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This file provides an Exim authenticator driver for
a server to verify a client SSL certificate, using the EXTERNAL
method defined in RFC 4422 Appendix A.
*/


#include "../exim.h"

#ifdef AUTH_EXTERNAL	/* Remainder of file */
#include "external.h"

/* Options specific to the external authentication mechanism. */

optionlist auth_external_options[] = {
  { "client_send",	opt_stringptr, OPT_OFF(auth_external_options_block, client_send) },
  { "server_param2",	opt_stringptr, OPT_OFF(auth_external_options_block, server_param2) },
  { "server_param3",	opt_stringptr, OPT_OFF(auth_external_options_block, server_param3) },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_external_options_count = nelem(auth_external_options);

/* Default private options block for the authentication method. */

auth_external_options_block auth_external_option_defaults = {
    .server_param2 = NULL,
    .server_param3 = NULL,

    .client_send = NULL,
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_external_init(driver_instance *ablock) {}
int auth_external_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_external_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/




/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_external_init(driver_instance * a)
{
auth_instance * ablock = (auth_instance *)a;
auth_external_options_block * ob = a->options_block;

if (!ablock->public_name)
  ablock->public_name = a->name;
if (ablock->server_condition)
  ablock->server = TRUE;
if (ob->client_send)
  ablock->client = TRUE;
}



/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_external_server(auth_instance * ablock, uschar * data)
{
auth_external_options_block * ob = ablock->drinst.options_block;
int rc;

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

if (expand_nmax == 0) 	/* skip if rxd data */
  if ((rc = auth_prompt(CUS"")) != OK)
    return rc;

if (ob->server_param2)
  {
  uschar * s = expand_string(ob->server_param2);
  auth_vars[expand_nmax = 1] = s;
  expand_nstring[++expand_nmax] = s;
  expand_nlength[expand_nmax] = Ustrlen(s);
  if (ob->server_param3)
    {
    s = expand_string(ob->server_param3);
    auth_vars[expand_nmax] = s;
    expand_nstring[++expand_nmax] = s;
    expand_nlength[expand_nmax] = Ustrlen(s);
    }
  }

return auth_check_serv_cond(ablock);
}



/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_external_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* smtp connextion */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* buffer for reading response */
  int buffsize)                          /* size of buffer */
{
const auth_external_options_block * ob = ablock->drinst.options_block;
const uschar * text = ob->client_send;
int rc;

/* We output an AUTH command with one expanded argument, the client_send option */

if ((rc = auth_client_item(sx, ablock, &text, AUTH_ITEM_FIRST | AUTH_ITEM_LAST,
      timeout, buffer, buffsize)) != OK)
  return rc == DEFER ? FAIL : rc;

if (text) auth_vars[0] = string_copy(text);
return OK;
}



# ifdef DYNLOOKUP
#  define external_auth_info _auth_info
# endif

auth_info external_auth_info = {
.drinfo = {
  .driver_name =	US"external",                   /* lookup name */
  .options =		auth_external_options,
  .options_count =	&auth_external_options_count,
  .options_block =	&auth_external_option_defaults,
  .options_len =	sizeof(auth_external_options_block),
  .init =		auth_external_init,
# ifdef DYNLOOKUP
  .dyn_magic =		AUTH_MAGIC,
# endif
  },
.servercode =		auth_external_server,
.clientcode =		auth_external_client,
.version_report =	NULL,
.macros_create =	NULL,
};

#endif	/*!MACRO_PREDEF*/
#endif	/*AUTH_EXTERNAL*/
/* End of external.c */
