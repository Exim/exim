/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "lf_functions.h"



/*************************************************
*    Call SQL server(s) to run an actual query   *
*************************************************/

/* All the SQL lookups are of the same form, with a list of servers to try
until one can be accessed. It is now also possible to provide the server data
as part of the query. This function manages server selection and looping; each
lookup has its own function for actually performing the lookup.

Arguments:
  name           the lookup name, e.g. "MySQL"
  optionname     the name of the servers option, e.g. "mysql_servers"
  optserverlist  the value of the servers option
  query          the query
  result         where to pass back the result
  errmsg         where to pass back an error message
  do_cache       to be set zero if data is changed
  func           the lookup function to call

Returns:         the return from the lookup function, or DEFER
*/

int
lf_sqlperform(const uschar *name, const uschar *optionname,
  const uschar *optserverlist, const uschar *query,
  uschar **result, uschar **errmsg, uint *do_cache, const uschar * opts,
  int(*fn)(const uschar *, uschar *, uschar **, uschar **, BOOL *, uint *, const uschar *))
{
int rc;
uschar *server;
BOOL defer_break = FALSE;

DEBUG(D_lookup) debug_printf_indent("%s query: \"%s\" opts '%s'\n", name, query, opts);

/* Handle queries that do have server information at the start. */

if (Ustrncmp(query, "servers", 7) == 0)
  {
  int qsep = 0;
  const uschar *s, *ss;
  const uschar *qserverlist;
  uschar *qserver;

  s = query + 7;
  skip_whitespace(&s);
  if (*s++ != '=')
    {
    *errmsg = string_sprintf("missing = after \"servers\" in %s lookup", name);
    return DEFER;
    }
  skip_whitespace(&s);

  ss = Ustrchr(s, ';');
  if (!ss)
    {
    *errmsg = string_sprintf("missing ; after \"servers=\" in %s lookup",
      name);
    return DEFER;
    }

  if (ss == s)
    {
    *errmsg = string_sprintf("\"servers=\" defines no servers in \"%s\"",
      query);
    return DEFER;
    }

  qserverlist = string_sprintf("%.*s", (int)(ss - s), s);

  while ((qserver = string_nextinlist(&qserverlist, &qsep, NULL, 0)))
    {
    if (Ustrchr(qserver, '/'))
      server = qserver;
    else
      {
      int len = Ustrlen(qserver);
      const uschar * serverlist = optserverlist;

      for (int sep = 0; server = string_nextinlist(&serverlist, &sep, NULL, 0);)
        if (Ustrncmp(server, qserver, len) == 0 && server[len] == '/')
          break;

      if (!server)
        {
        *errmsg = string_sprintf("%s server \"%s\" not found in %s", name,
          qserver, optionname);
        return DEFER;
        }
      }

    { uschar *m;
    if ((m = is_tainted2(server, 0, "Tainted %s server '%s'", name, server)))
     {
      *errmsg = m;
      return DEFER;
      }
    }

    rc = (*fn)(ss+1, server, result, errmsg, &defer_break, do_cache, opts);
    if (rc != DEFER || defer_break) return rc;
    }
  }

/* Handle queries that do not have server information at the start. */

else
  {
  const uschar * serverlist = NULL;

  /* If options are present, scan for a server definition.  Default to
  the "optserverlist" srgument. */

  if (opts)
    {
    uschar * ele;
    for (int sep = ','; ele = string_nextinlist(&opts, &sep, NULL, 0); )
      if (Ustrncmp(ele, "servers=", 8) == 0)
	{ serverlist = ele + 8; break; }
    }

  if (!serverlist)
    serverlist = optserverlist;
  if (!serverlist)
    *errmsg = string_sprintf("no %s servers defined (%s option)", name,
      optionname);
  else
    for (int d = 0; (server = string_nextinlist(&serverlist, &d, NULL, 0)); )
      {
      /* If not a full spec assume from options; scan main list for matching
      hostname */

      if (!Ustrchr(server, '/'))
	{
	int len = Ustrlen(server);
	const uschar * slist = optserverlist;
	uschar * ele;
	for (int sep = 0; ele = string_nextinlist(&slist, &sep, NULL, 0); )
	  if (Ustrncmp(ele, server, len) == 0 && ele[len] == '/')
	    break;
	if (!ele)
	  {
	  *errmsg = string_sprintf("%s server \"%s\" not found in %s", name,
	    server, optionname);
	  return DEFER;
	  }
	server = ele;
	}

      { uschar *m;
      if ((m = is_tainted2(server, 0, "Tainted %s server '%s'", name, server)))
        {
        *errmsg = m;
        return DEFER;
        }
      }

      rc = (*fn)(query, server, result, errmsg, &defer_break, do_cache, opts);
      if (rc != DEFER || defer_break) return rc;
      }
  }

return DEFER;
}

/* End of lf_sqlperform.c */
