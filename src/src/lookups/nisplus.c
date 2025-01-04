/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"
#include "lf_functions.h"

#include <rpcsvc/nis.h>


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
nisplus_open(const uschar * filename, uschar ** errmsg)
{
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The format of queries for a
NIS+ search is

  [field=value,...],table-name
or
  [field=value,...],table-name:result-field-name

in other words, a normal NIS+ "indexed name", with an optional result field
name tagged on the end after a colon. If there is no result-field name, the
yield is the concatenation of all the fields, preceded by their names and an
equals sign. */

static int
nisplus_find(void * handle, const uschar * filename, const uschar * query,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
int error_error = FAIL;
const uschar * field_name = NULL;
nis_result *nrt = NULL;
nis_result *nre = NULL;
nis_object *tno, *eno;
struct entry_obj *eo;
struct table_obj *ta;
const uschar * p = query + length;
gstring * yield = NULL;

do_cache = do_cache;   /* Placate picky compilers */

/* Search backwards for a colon to see if a result field name
has been given. */

while (p > query && p[-1] != ':') p--;

if (p > query)		/* get the query without the result-field */
  {
  uint len = p-1 - query;
  field_name = p;
  query = string_copyn(query, len);
  p = query + len;
  }
else
  p = query + length;

/* Now search backwards to find the comma that starts the
table name. */

while (p > query && p[-1] != ',') p--;
if (p <= query)
  {
  *errmsg = US"NIS+ query malformed";
  error_error = DEFER;
  goto NISPLUS_EXIT;
  }

/* Look up the data for the table, in order to get the field names,
check that we got back a table, and set up pointers so the field
names can be scanned. */

nrt = nis_lookup(CS p, EXPAND_NAME | NO_CACHE);
if (nrt->status != NIS_SUCCESS)
  {
  *errmsg = string_sprintf("NIS+ error accessing %s table: %s", p,
    nis_sperrno(nrt->status));
  if (nrt->status != NIS_NOTFOUND && nrt->status != NIS_NOSUCHTABLE)
    error_error = DEFER;
  goto NISPLUS_EXIT;
  }
tno = nrt->objects.objects_val;
if (tno->zo_data.zo_type != TABLE_OBJ)
  {
  *errmsg = string_sprintf("NIS+ error: %s is not a table", p);
  goto NISPLUS_EXIT;
  }
ta = &tno->zo_data.objdata_u.ta_data;

/* Now look up the entry in the table, check that we got precisely one
object and that it is a table entry. */

nre = nis_list(CS query, EXPAND_NAME, NULL, NULL);
if (nre->status != NIS_SUCCESS)
  {
  *errmsg = string_sprintf("NIS+ error accessing entry %s: %s",
    query, nis_sperrno(nre->status));
  goto NISPLUS_EXIT;
  }
if (nre->objects.objects_len > 1)
  {
  *errmsg = string_sprintf("NIS+ returned more than one object for %s",
    query);
  goto NISPLUS_EXIT;
  }
else if (nre->objects.objects_len < 1)
  {
  *errmsg = string_sprintf("NIS+ returned no data for %s", query);
  goto NISPLUS_EXIT;
  }
eno = nre->objects.objects_val;
if (eno->zo_data.zo_type != ENTRY_OBJ)
  {
  *errmsg = string_sprintf("NIS+ error: %s is not an entry", query);
  goto NISPLUS_EXIT;
  }

/* Scan the columns in the entry and in the table. If a result field
was given, look for that field; otherwise concatenate all the fields
with their names. */

eo = &(eno->zo_data.objdata_u.en_data);
for (int i = 0; i < eo->en_cols.en_cols_len; i++)
  {
  const table_col * tc = ta->ta_cols.ta_cols_val + i;
  const entry_col * ec = eo->en_cols.en_cols_val + i;
  int len = ec->ec_value.ec_value_len;
  const uschar * value = US ec->ec_value.ec_value_val;

  /* The value may be NULL for a zero-length field. Turn this into an
  empty string for consistency. Remove trailing whitespace and zero
  bytes. */

  if (!value) value = US"";
  else
    while (len > 0 && (value[len-1] == 0 || isspace(value[len-1])))
      len--;

  /* Concatenate all fields if no specific one selected */

  if (!field_name)
    {
    yield = string_cat (yield, US tc->tc_name);
    yield = string_catn(yield, US"=", 1);

    /* Quote the value if it contains spaces or is empty */

    if (value[0] == 0 || Ustrchr(value, ' ') != NULL)
      {
      yield = string_catn(yield, US"\"", 1);
      for (int j = 0; j < len; j++)
        {
        if (value[j] == '\"' || value[j] == '\\')
          yield = string_catn(yield, US"\\", 1);
        yield = string_catn(yield, value+j, 1);
        }
      yield = string_catn(yield, US"\"", 1);
      }
    else
      yield = string_catn(yield, value, len);

    yield = string_catn(yield, US" ", 1);
    }

  /* When the specified field is found, grab its data and finish */

  else if (Ustrcmp(field_name, tc->tc_name) == 0)
    {
    yield = string_catn(yield, value, len);
    goto NISPLUS_EXIT;
    }
  }

/* Error if a field name was specified and we didn't find it; if no
field name, ensure the concatenated data is zero-terminated. */

if (field_name)
  *errmsg = string_sprintf("NIS+ field %s not found for %s", field_name,
    query);
else
  gstring_release_unused(yield);

/* Free result store before finishing. */

NISPLUS_EXIT:
if (nrt) nis_freeresult(nrt);
if (nre) nis_freeresult(nre);

if (yield)
  {
  *result = string_from_gstring(yield);
  return OK;
  }

return error_error;      /* FAIL or DEFER */
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* The only quoting that is necessary for NIS+ is to double any doublequote
characters. No options are recognized.

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none
  idx	     lookup type index

Returns:     the processed string or NULL for a bad option
*/

static uschar *
nisplus_quote(uschar * s, uschar * opt, unsigned idx)
{
int count = 0;
uschar * quoted, * t = s;

if (opt) return NULL;    /* No options recognized */

while (*t) if (*t++ == '\"') count++;

t = quoted = store_get_quoted(Ustrlen(s) + count + 1, s, idx, US"nisplus");

while (*s)
  {
  *t++ = *s;
  if (*s++ == '\"') *t++ = '\"';
  }

*t = 0;
return quoted;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
nisplus_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: NIS+: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


static lookup_info _lookup_info = {
  .name = US"nisplus",			/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = nisplus_open,			/* open function */
  .check = NULL,			/* check function */
  .find = nisplus_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = nisplus_quote,		/* quoting function */
  .version_report = nisplus_version_report         /* version reporting */
};

#ifdef DYNLOOKUP
#define nisplus_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info nisplus_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/nisplus.c */
