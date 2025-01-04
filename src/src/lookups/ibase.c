/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* The code in this module was contributed by Ard Biesheuvel. */

#include "../exim.h"
#include "lf_functions.h"

#include <ibase.h>              /* The system header */

/* Structure and anchor for caching connections. */

typedef struct ibase_connection {
    struct ibase_connection *next;
    uschar *server;
    isc_db_handle dbh;
    isc_tr_handle transh;
} ibase_connection;

static ibase_connection *ibase_connections = NULL;


#if defined(_LP64) || defined(__LP64__) || defined(__arch64__) || defined(_WIN64)
# define ISC_NULL 0
#else
# define ISC_NULL NULL
#endif

/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *ibase_open(const uschar * filename, uschar ** errmsg)
{
return (void *) (1);        /* Just return something non-null */
}



/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description. */

static void
ibase_tidy(void)
{
ibase_connection *cn;
ISC_STATUS status[20];

while ((cn = ibase_connections))
  {
  ibase_connections = cn->next;
  DEBUG(D_lookup) debug_printf_indent("close Interbase connection: %s\n",
			       cn->server);
  isc_commit_transaction(status, &cn->transh);
  isc_detach_database(status, &cn->dbh);
  }
}

static int
fetch_field(uschar * buffer, int buffer_size, XSQLVAR * var)
{
if (buffer_size < var->sqllen)
  return 0;

switch (var->sqltype & ~1)
  {
  case SQL_VARYING:
      strncpy(CS buffer, &var->sqldata[2], *(short *) var->sqldata);
      return *(short *) var->sqldata;
  case SQL_TEXT:
      strncpy(CS buffer, var->sqldata, var->sqllen);
      return var->sqllen;
  case SQL_SHORT:
      return sprintf(CS buffer, "%d", *(short *) var->sqldata);
  case SQL_LONG:
      return sprintf(CS buffer, "%ld", *(ISC_LONG *) var->sqldata);
  #ifdef SQL_INT64
  case SQL_INT64:
      return sprintf(CS buffer, "%lld", *(ISC_INT64 *) var->sqldata);
  #endif
  default:
      /* not implemented */
      return 0;
  }
}

/*************************************************
*        Internal search function                *
*************************************************/

/* This function is called from the find entry point to do the search for a
single server.

Arguments:
  query        the query string
  server       the server string
  resultptr    where to store the result
  errmsg       where to point an error message
  defer_break  TRUE if no more servers are to be tried after DEFER

The server string is of the form "host:dbname|user|password". The host can be
host:port. This string is in a nextinlist temporary buffer, so can be
overwritten.

Returns:       OK, FAIL, or DEFER
*/

static int
perform_ibase_search(const uschar * query, uschar * server, uschar ** resultptr,
                     uschar ** errmsg, BOOL * defer_break)
{
isc_stmt_handle stmth;
XSQLDA *out_sqlda;
XSQLVAR *var;
int i;
rmark reset_point;

uschar buffer[256];
ISC_STATUS status[20], *statusp = status;

gstring * result = NULL;
int yield = DEFER;
ibase_connection *cn;
uschar *server_copy = NULL;
uschar *sdata[3];

/* Disaggregate the parameters from the server argument. The order is host,
database, user, password. We can write to the string, since it is in a
nextinlist temporary buffer. The copy of the string that is used for caching
has the password removed. This copy is also used for debugging output. */

for (int i = 2; i > 0; i--)
  {
  uschar * pp = Ustrrchr(server, '|');

  if (!pp)
    {
    *errmsg = string_sprintf("incomplete Interbase server data: %s",
		       i == 3 ? server : server_copy);
    *defer_break = TRUE;
    return DEFER;
    }
  *pp++ = 0;
  sdata[i] = pp;
  if (i == 2)
      server_copy = string_copy(server);   /* sans password */
  }
sdata[0] = server;          /* What's left at the start */

/* See if we have a cached connection to the server */

for (cn = ibase_connections; cn; cn = cn->next)
  if (Ustrcmp(cn->server, server_copy) == 0)
    break;

/* Use a previously cached connection ? */

if (cn)
  {
  static char db_info_options[] = { isc_info_base_level };

  /* test if the connection is alive */
  if (isc_database_info(status, &cn->dbh, sizeof(db_info_options),
	db_info_options, sizeof(buffer), CS buffer))
    {
    /* error occurred: assume connection is down */
    DEBUG(D_lookup)
      debug_printf("Interbase cleaning up cached connection: %s\n", cn->server);
    isc_detach_database(status, &cn->dbh);
    }
  else
    DEBUG(D_lookup)
      debug_printf_indent("Interbase using cached connection for %s\n",
		     server_copy);
  }
else
  {
  cn = store_get(sizeof(ibase_connection), GET_UNTAINTED);
  cn->server = server_copy;
  cn->dbh = ISC_NULL;
  cn->transh = ISC_NULL;
  cn->next = ibase_connections;
  ibase_connections = cn;
  }

/* If no cached connection, we must set one up. */

if (!cn->dbh || !cn->transh)
  {
  uschar * dpb;
  short dpb_length;
  static char trans_options[] =
      { isc_tpb_version3, isc_tpb_read, isc_tpb_read_committed,
      isc_tpb_rec_version };

  /* Construct the database parameter buffer. */
  dpb = buffer;
  *dpb++ = isc_dpb_version1;
  *dpb++ = isc_dpb_user_name;
  *dpb++ = Ustrlen(sdata[1]);
  for (uschar * p = sdata[1]; *p;) *dpb++ = *p++;
  *dpb++ = isc_dpb_password;
  *dpb++ = Ustrlen(sdata[2]);
  for (uschar * p = sdata[2]; *p;) *dpb++ = *p++;
  dpb_length = dpb - buffer;

  DEBUG(D_lookup)
      debug_printf_indent("new Interbase connection: database=%s user=%s\n",
		   sdata[0], sdata[1]);

  /* Connect to the database */
  if (isc_attach_database(status, 0, CS sdata[0], &cn->dbh,
			  dpb_length, CS buffer))
    {
    isc_interprete(CS buffer, &statusp);
    *errmsg = string_sprintf("Interbase attach() failed: %s", buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }

  /* Now start a read-only read-committed transaction */
  if (isc_start_transaction(status, &cn->transh, 1, &cn->dbh,
			    sizeof(trans_options), trans_options))
    {
    isc_interprete(CS buffer, &statusp);
    isc_detach_database(status, &cn->dbh);
    *errmsg = string_sprintf("Interbase start_transaction() failed: %s",
		       buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }
  }

/* Run the query */
if (isc_dsql_allocate_statement(status, &cn->dbh, &stmth))
  {
  isc_interprete(CS buffer, &statusp);
  *errmsg = string_sprintf("Interbase alloc_statement() failed: %s", buffer);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

/* Lacking any information, assume that the data is untainted */
reset_point = store_mark();
out_sqlda = store_get(XSQLDA_LENGTH(1), GET_UNTAINTED);
out_sqlda->version = SQLDA_VERSION1;
out_sqlda->sqln = 1;

if (isc_dsql_prepare(status, &cn->transh, &stmth, 0, CCS query, 1, out_sqlda))
  {
  isc_interprete(CS buffer, &statusp);
  reset_point = store_reset(reset_point);
  out_sqlda = NULL;
  *errmsg = string_sprintf("Interbase prepare_statement() failed: %s", buffer);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

/* re-allocate the output structure if there's more than one field */
if (out_sqlda->sqln < out_sqlda->sqld)
  {
  XSQLDA *new_sqlda = store_get(XSQLDA_LENGTH(out_sqlda->sqld), GET_UNTAINTED);
  if (isc_dsql_describe
      (status, &stmth, out_sqlda->version, new_sqlda))
    {
    isc_interprete(CS buffer, &statusp);
    isc_dsql_free_statement(status, &stmth, DSQL_drop);
    reset_point = store_reset(reset_point);
    out_sqlda = NULL;
    *errmsg = string_sprintf("Interbase describe_statement() failed: %s",
		       buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }
  out_sqlda = new_sqlda;
  }

/* allocate storage for every returned field */
for (i = 0, var = out_sqlda->sqlvar; i < out_sqlda->sqld; i++, var++)
  {
  switch (var->sqltype & ~1)
    {
    case SQL_VARYING:
	var->sqldata = CS store_get(sizeof(char) * var->sqllen + 2, GET_UNTAINTED);
	break;
    case SQL_TEXT:
	var->sqldata = CS store_get(sizeof(char) * var->sqllen, GET_UNTAINTED);
	break;
    case SQL_SHORT:
	var->sqldata = CS  store_get(sizeof(short), GET_UNTAINTED);
	break;
    case SQL_LONG:
	var->sqldata = CS  store_get(sizeof(ISC_LONG), GET_UNTAINTED);
	break;
#ifdef SQL_INT64
    case SQL_INT64:
	var->sqldata = CS  store_get(sizeof(ISC_INT64), GET_UNTAINTED);
	break;
#endif
    case SQL_FLOAT:
	var->sqldata = CS  store_get(sizeof(float), GET_UNTAINTED);
	break;
    case SQL_DOUBLE:
	var->sqldata = CS  store_get(sizeof(double), GET_UNTAINTED);
	break;
#ifdef SQL_TIMESTAMP
    case SQL_DATE:
	var->sqldata = CS  store_get(sizeof(ISC_QUAD), GET_UNTAINTED);
	break;
#else
    case SQL_TIMESTAMP:
	var->sqldata = CS  store_get(sizeof(ISC_TIMESTAMP), GET_UNTAINTED);
	break;
    case SQL_TYPE_DATE:
	var->sqldata = CS  store_get(sizeof(ISC_DATE), GET_UNTAINTED);
	break;
    case SQL_TYPE_TIME:
	var->sqldata = CS  store_get(sizeof(ISC_TIME), GET_UNTAINTED);
	break;
  #endif
    }
  if (var->sqltype & 1)
    var->sqlind = (short *) store_get(sizeof(short), GET_UNTAINTED);
  }

/* finally, we're ready to execute the statement */
if (isc_dsql_execute(status, &cn->transh, &stmth, out_sqlda->version, NULL))
  {
  isc_interprete(CS buffer, &statusp);
  *errmsg = string_sprintf("Interbase describe_statement() failed: %s", buffer);
  isc_dsql_free_statement(status, &stmth, DSQL_drop);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

while (isc_dsql_fetch(status, &stmth, out_sqlda->version, out_sqlda) != 100L)
  {
  /* check if an error occurred */
  if (status[0] & status[1])
    {
    isc_interprete(CS buffer, &statusp);
    *errmsg = string_sprintf("Interbase fetch() failed: %s", buffer);
    isc_dsql_free_statement(status, &stmth, DSQL_drop);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }

  if (result)
    result = string_catn(result, US "\n", 1);

  /* Find the number of fields returned. If this is one, we don't add field
     names to the data. Otherwise we do. */
  if (out_sqlda->sqld == 1)
    {
    if (out_sqlda->sqlvar[0].sqlind == NULL || *out_sqlda->sqlvar[0].sqlind != -1)     /* NULL value yields nothing */
      result = string_catn(result, US buffer,
		   fetch_field(buffer, sizeof(buffer), &out_sqlda->sqlvar[0]));
    }

  else
    for (int i = 0; i < out_sqlda->sqld; i++)
      {
      int len = fetch_field(buffer, sizeof(buffer), &out_sqlda->sqlvar[i]);

      result = string_catn(result, US out_sqlda->sqlvar[i].aliasname,
		     out_sqlda->sqlvar[i].aliasname_length);
      result = string_catn(result, US "=", 1);

      /* Quote the value if it contains spaces or is empty */

      if (*out_sqlda->sqlvar[i].sqlind == -1)       /* NULL value */
	result = string_catn(result, US "\"\"", 2);

      else if (buffer[0] == 0 || Ustrchr(buffer, ' ') != NULL)
	{
	result = string_catn(result, US "\"", 1);
	for (int j = 0; j < len; j++)
	  {
	  if (buffer[j] == '\"' || buffer[j] == '\\')
	      result = string_catn(result, US "\\", 1);
	  result = string_catn(result, US buffer + j, 1);
	  }
	result = string_catn(result, US "\"", 1);
	}
      else
	result = string_catn(result, US buffer, len);
      result = string_catn(result, US " ", 1);
      }
  }

/* If result is NULL then no data has been found and so we return FAIL.
Otherwise, we must terminate the string which has been built; string_cat()
always leaves enough room for a terminating zero. */

if (!result)
  {
  yield = FAIL;
  *errmsg = US "Interbase: no data found";
  }
else
  gstring_release_unused(result);


/* Get here by goto from various error checks. */

IBASE_EXIT:

if (stmth)
  isc_dsql_free_statement(status, &stmth, DSQL_drop);

/* Non-NULL result indicates a successful result */

if (result)
  {
  *resultptr = string_from_gstring(result);
  return OK;
  }
else
  {
  DEBUG(D_lookup) debug_printf_indent("%s\n", *errmsg);
  return yield;           /* FAIL or DEFER */
  }
}




/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The handle and filename
arguments are not used. Loop through a list of servers while the query is
deferred with a retryable error. */

static int
ibase_find(void * handle, const uschar * filename, const uschar * query,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
uschar * server;
const uschar * list = ibase_servers;

DEBUG(D_lookup) debug_printf_indent("Interbase query: %s\n", query);

for (int sep = 0; server = string_nextinlist(&list, &sep, NULL, 0); )
  {
  BOOL defer_break = FALSE;
  int rc = perform_ibase_search(query, server, result, errmsg, &defer_break);
  if (rc != DEFER || defer_break)
    return rc;
  }

if (!ibase_servers)
  *errmsg = US "no Interbase servers defined (ibase_servers option)";

return DEFER;
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* The only characters that need to be quoted (with backslash) are newline,
tab, carriage return, backspace, backslash itself, and the quote characters.
Percent, and underscore and not escaped. They are only special in contexts
where they can be wild cards, and this isn't usually the case for data inserted
from messages, since that isn't likely to be treated as a pattern of any kind.
Sadly, MySQL doesn't seem to behave like other programs. If you use something
like "where id="ab\%cd" it does not treat the string as "ab%cd". So you really
can't quote "on spec".

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none
  idx	     lookup type index

Returns:     the processed string or NULL for a bad option
*/

static uschar *
ibase_quote(uschar * s, const uschar * opt, unsigned idx)
{
gstring * quoted = store_get_quoted(1, s, idx, US"ibase");

if (opt)
  return NULL;            /* No options recognized */

for (uschar c; c = *s; s++)
  {
  if (c == '\'') quoted = string_catn(quoted, US"\\", 1);
  quoted = string_catn(quoted, s, 1);
  }
gstring_release_unused(quoted);
return(string_from_gstring(quoted));
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
ibase_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: ibase: Exim version %s\n", EXIM_VERSION_STR));
#endif
return g;
}


static lookup_info _lookup_info = {
  .name = US"ibase",			/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = ibase_open,			/* open function */
  .check = NULL,			/* no check function */
  .find = ibase_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = ibase_tidy,			/* tidy function */
  .quote = ibase_quote,			/* quoting function */
  .version_report = ibase_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
#define ibase_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info ibase_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/ibase.c */
