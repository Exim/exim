/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Thanks to Paul Kelly for contributing the original code for these
functions. */


#include "../exim.h"
#include "lf_functions.h"

#include <mysql.h>       /* The system header */


/* Structure and anchor for caching connections. */

typedef struct mysql_connection {
  struct mysql_connection *next;
  uschar  *server;
  MYSQL *handle;
} mysql_connection;

static mysql_connection *mysql_connections = NULL;



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
mysql_open(uschar *filename, uschar **errmsg)
{
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description. */

static void
mysql_tidy(void)
{
mysql_connection *cn;
while ((cn = mysql_connections) != NULL)
  {
  mysql_connections = cn->next;
  DEBUG(D_lookup) debug_printf("close MYSQL connection: %s\n", cn->server);
  mysql_close(cn->handle);
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
  do_cache     set false if data is changed

The server string is of the form "host/dbname/user/password". The host can be
host:port. This string is in a nextinlist temporary buffer, so can be
overwritten.

Returns:       OK, FAIL, or DEFER
*/

static int
perform_mysql_search(const uschar *query, uschar *server, uschar **resultptr,
  uschar **errmsg, BOOL *defer_break, BOOL *do_cache)
{
MYSQL *mysql_handle = NULL;        /* Keep compilers happy */
MYSQL_RES *mysql_result = NULL;
MYSQL_ROW mysql_row_data;
MYSQL_FIELD *fields;

int i;
int ssize = 0;
int offset = 0;
int yield = DEFER;
unsigned int num_fields;
uschar *result = NULL;
mysql_connection *cn;
uschar *server_copy = NULL;
uschar *sdata[4];

/* Disaggregate the parameters from the server argument. The order is host,
database, user, password. We can write to the string, since it is in a
nextinlist temporary buffer. The copy of the string that is used for caching
has the password removed. This copy is also used for debugging output. */

for (i = 3; i > 0; i--)
  {
  uschar *pp = Ustrrchr(server, '/');
  if (pp == NULL)
    {
    *errmsg = string_sprintf("incomplete MySQL server data: %s",
      (i == 3)? server : server_copy);
    *defer_break = TRUE;
    return DEFER;
    }
  *pp++ = 0;
  sdata[i] = pp;
  if (i == 3) server_copy = string_copy(server);  /* sans password */
  }
sdata[0] = server;   /* What's left at the start */

/* See if we have a cached connection to the server */

for (cn = mysql_connections; cn != NULL; cn = cn->next)
  {
  if (Ustrcmp(cn->server, server_copy) == 0)
    {
    mysql_handle = cn->handle;
    break;
    }
  }

/* If no cached connection, we must set one up. Mysql allows for a host name
and port to be specified. It also allows the name of a Unix socket to be used.
Unfortunately, this contains slashes, but its use is expected to be rare, so
the rather cumbersome syntax shouldn't inconvenience too many people. We use
this:  host:port(socket)  where all the parts are optional. */

if (cn == NULL)
  {
  uschar *p;
  uschar *socket = NULL;
  int port = 0;

  if ((p = Ustrchr(sdata[0], '(')) != NULL)
    {
    *p++ = 0;
    socket = p;
    while (*p != 0 && *p != ')') p++;
    *p = 0;
    }

  if ((p = Ustrchr(sdata[0], ':')) != NULL)
    {
    *p++ = 0;
    port = Uatoi(p);
    }

  if (Ustrchr(sdata[0], '/') != NULL)
    {
    *errmsg = string_sprintf("unexpected slash in MySQL server hostname: %s",
      sdata[0]);
    *defer_break = TRUE;
    return DEFER;
    }

  /* If the database is the empty string, set it NULL - the query must then
  define it. */

  if (sdata[1][0] == 0) sdata[1] = NULL;

  DEBUG(D_lookup)
    debug_printf("MYSQL new connection: host=%s port=%d socket=%s "
      "database=%s user=%s\n", sdata[0], port, socket, sdata[1], sdata[2]);

  /* Get store for a new handle, initialize it, and connect to the server */

  mysql_handle = store_get(sizeof(MYSQL));
  mysql_init(mysql_handle);
  if (mysql_real_connect(mysql_handle,
      /*  host        user         passwd     database */
      CS sdata[0], CS sdata[2], CS sdata[3], CS sdata[1],
      port, CS socket, CLIENT_MULTI_RESULTS) == NULL)
    {
    *errmsg = string_sprintf("MYSQL connection failed: %s",
      mysql_error(mysql_handle));
    *defer_break = FALSE;
    goto MYSQL_EXIT;
    }

  /* Add the connection to the cache */

  cn = store_get(sizeof(mysql_connection));
  cn->server = server_copy;
  cn->handle = mysql_handle;
  cn->next = mysql_connections;
  mysql_connections = cn;
  }

/* Else use a previously cached connection */

else
  {
  DEBUG(D_lookup)
    debug_printf("MYSQL using cached connection for %s\n", server_copy);
  }

/* Run the query */

if (mysql_query(mysql_handle, CS query) != 0)
  {
  *errmsg = string_sprintf("MYSQL: query failed: %s\n",
    mysql_error(mysql_handle));
  *defer_break = FALSE;
  goto MYSQL_EXIT;
  }

/* Pick up the result. If the query was not of the type that returns data,
namely INSERT, UPDATE, or DELETE, an error occurs here. However, this situation
can be detected by calling mysql_field_count(). If its result is zero, no data
was expected (this is all explained clearly in the MySQL manual). In this case,
we return the number of rows affected by the command. In this event, we do NOT
want to cache the result; also the whole cache for the handle must be cleaned
up. Setting do_cache FALSE requests this. */

if ((mysql_result = mysql_use_result(mysql_handle)) == NULL)
  {
  if ( mysql_field_count(mysql_handle) == 0 )
    {
    DEBUG(D_lookup) debug_printf("MYSQL: query was not one that returns data\n");
    result = string_sprintf("%d", mysql_affected_rows(mysql_handle));
    *do_cache = FALSE;
    goto MYSQL_EXIT;
    }
  *errmsg = string_sprintf("MYSQL: lookup result failed: %s\n",
    mysql_error(mysql_handle));
  *defer_break = FALSE;
  goto MYSQL_EXIT;
  }

/* Find the number of fields returned. If this is one, we don't add field
names to the data. Otherwise we do. */

num_fields = mysql_num_fields(mysql_result);

/* Get the fields and construct the result string. If there is more than one
row, we insert '\n' between them. */

fields = mysql_fetch_fields(mysql_result);

while ((mysql_row_data = mysql_fetch_row(mysql_result)) != NULL)
  {
  unsigned long *lengths = mysql_fetch_lengths(mysql_result);

  if (result != NULL)
      result = string_cat(result, &ssize, &offset, US"\n", 1);

  if (num_fields == 1)
    {
    if (mysql_row_data[0] != NULL)    /* NULL value yields nothing */
      result = string_cat(result, &ssize, &offset, US mysql_row_data[0],
        lengths[0]);
    }

  else for (i = 0; i < num_fields; i++)
    {
    result = lf_quote(US fields[i].name, US mysql_row_data[i], lengths[i],
      result, &ssize, &offset);
    }
  }

/* more results? -1 = no, >0 = error, 0 = yes (keep looping)
   This is needed because of the CLIENT_MULTI_RESULTS on mysql_real_connect(),
   we don't expect any more results. */

while((i = mysql_next_result(mysql_handle)) >= 0) {
   if(i == 0) {   /* Just ignore more results */
     DEBUG(D_lookup) debug_printf("MYSQL: got unexpected more results\n");
     continue;
   }

   *errmsg = string_sprintf("MYSQL: lookup result error when checking for more results: %s\n",
       mysql_error(mysql_handle));
   goto MYSQL_EXIT;
}

/* If result is NULL then no data has been found and so we return FAIL.
Otherwise, we must terminate the string which has been built; string_cat()
always leaves enough room for a terminating zero. */

if (result == NULL)
  {
  yield = FAIL;
  *errmsg = US"MYSQL: no data found";
  }
else
  {
  result[offset] = 0;
  store_reset(result + offset + 1);
  }

/* Get here by goto from various error checks and from the case where no data
was read (e.g. an update query). */

MYSQL_EXIT:

/* Free mysal store for any result that was got; don't close the connection, as
it is cached. */

if (mysql_result != NULL) mysql_free_result(mysql_result);

/* Non-NULL result indicates a sucessful result */

if (result != NULL)
  {
  *resultptr = result;
  return OK;
  }
else
  {
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return yield;      /* FAIL or DEFER */
  }
}




/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The handle and filename
arguments are not used. The code to loop through a list of servers while the
query is deferred with a retryable error is now in a separate function that is
shared with other SQL lookups. */

static int
mysql_find(void *handle, uschar *filename, const uschar *query, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
return lf_sqlperform(US"MySQL", US"mysql_servers", mysql_servers, query,
  result, errmsg, do_cache, perform_mysql_search);
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

Returns:     the processed string or NULL for a bad option
*/

static uschar *
mysql_quote(uschar *s, uschar *opt)
{
register int c;
int count = 0;
uschar *t = s;
uschar *quoted;

if (opt != NULL) return NULL;     /* No options recognized */

while ((c = *t++) != 0)
  if (Ustrchr("\n\t\r\b\'\"\\", c) != NULL) count++;

if (count == 0) return s;
t = quoted = store_get(Ustrlen(s) + count + 1);

while ((c = *s++) != 0)
  {
  if (Ustrchr("\n\t\r\b\'\"\\", c) != NULL)
    {
    *t++ = '\\';
    switch(c)
      {
      case '\n': *t++ = 'n';
      break;
      case '\t': *t++ = 't';
      break;
      case '\r': *t++ = 'r';
      break;
      case '\b': *t++ = 'b';
      break;
      default:   *t++ = c;
      break;
      }
    }
  else *t++ = c;
  }

*t = 0;
return quoted;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
mysql_version_report(FILE *f)
{
fprintf(f, "Library version: MySQL: Compile: %s [%s]\n"
           "                        Runtime: %s\n",
        MYSQL_SERVER_VERSION, MYSQL_COMPILATION_COMMENT,
        mysql_get_client_info());
#ifdef DYNLOOKUP
fprintf(f, "                        Exim version %s\n", EXIM_VERSION_STR);
#endif
}

/* These are the lookup_info blocks for this driver */

static lookup_info mysql_lookup_info = {
  US"mysql",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  mysql_open,                    /* open function */
  NULL,                          /* no check function */
  mysql_find,                    /* find function */
  NULL,                          /* no close function */
  mysql_tidy,                    /* tidy function */
  mysql_quote,                   /* quoting function */
  mysql_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
#define mysql_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &mysql_lookup_info };
lookup_module_info mysql_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/mysql.c */
