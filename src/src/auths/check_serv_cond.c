/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"

/* This module contains the function server_condition(), which is used
by all authenticators. */


/*************************************************
*              Check server_condition            *
*************************************************/

/* This function is called from the server code of all authenticators. For
plaintext, it is always called: the argument cannot be empty, because for
plaintext, setting server_condition is what enables it as a server
authenticator. For all the other authenticators, this function is called after
they have authenticated, to enable additional authorization to be done.

Argument:     the authenticator's instance block

Returns:
  OK          NULL argument, or success
  DEFER       couldn't complete the check
  FAIL        authentication failed
*/

int
auth_check_serv_cond(auth_instance *ablock)
{
uschar *cond;

HDEBUG(D_auth)
  {
  int i;
  debug_printf("%s authenticator:\n", ablock->name);
  for (i = 0; i < AUTH_VARS; i++)
    {
    if (auth_vars[i] != NULL)
      debug_printf("  $auth%d = %s\n", i + 1, auth_vars[i]);
    }
  for (i = 1; i <= expand_nmax; i++)
    debug_printf("  $%d = %.*s\n", i, expand_nlength[i], expand_nstring[i]);
  debug_print_string(ablock->server_debug_string);    /* customized debug */
  }

/* For the plaintext authenticator, server_condition is never NULL. For the
rest, an unset condition lets everything through. */

if (ablock->server_condition == NULL) return OK;
cond = expand_string(ablock->server_condition);

HDEBUG(D_auth)
  {
  if (cond == NULL)
    debug_printf("expansion failed: %s\n", expand_string_message);
  else
    debug_printf("expanded string: %s\n", cond);
  }

/* A forced expansion failure causes authentication to fail. Other expansion
failures yield DEFER, which will cause a temporary error code to be returned to
the AUTH command. The problem is at the server end, so the client should try
again later. */

if (cond == NULL)
  {
  if (expand_string_forcedfail) return FAIL;
  auth_defer_msg = expand_string_message;
  return DEFER;
  }

/* Return FAIL for empty string, "0", "no", and "false"; return OK for
"1", "yes", and "true"; return DEFER for anything else, with the string
available as an error text for the user. */

if (*cond == 0 ||
    Ustrcmp(cond, "0") == 0 ||
    strcmpic(cond, US"no") == 0 ||
    strcmpic(cond, US"false") == 0)
  return FAIL;

if (Ustrcmp(cond, "1") == 0 ||
    strcmpic(cond, US"yes") == 0 ||
    strcmpic(cond, US"true") == 0)
  return OK;

auth_defer_msg = cond;
auth_defer_user_msg = string_sprintf(": %s", cond);
return DEFER;
}

/* End of check_serv_cond.c */
