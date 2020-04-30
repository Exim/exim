/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2019-2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"
#include <jansson.h>



/* All use of allocations will be done against the POOL_SEARCH memory,
which is freed once by search_tidyup(). Make the free call a dummy.
This burns some 300kB in handling a 37kB JSON file, for the benefit of
a fast free.  The alternative of staying with malloc is nearly as bad,
eyeballing the activity there are 20% the number of free vs. alloc
calls (before the big bunch at the end).

Assume that the file is trusted, so no tainting */

static void *
json_malloc(size_t nbytes)
{
void * p = store_get((int)nbytes, FALSE);
/* debug_printf("%s %d: %p\n", __FUNCTION__, (int)nbytes, p); */
return p;
}
static void
json_free(void * p)
{
/* debug_printf("%s: %p\n", __FUNCTION__, p); */
}

/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
json_open(const uschar * filename, uschar ** errmsg)
{
FILE * f;

json_set_alloc_funcs(json_malloc, json_free);

if (!(f = Ufopen(filename, "rb")))
  {
  int save_errno = errno;
  *errmsg = string_open_failed(errno, "%s for json search", filename);
  errno = save_errno;
  return NULL;
  }
return f;
}



/*************************************************
*             Check entry point                  *
*************************************************/

static BOOL
json_check(void *handle, const uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
return lf_check_file(fileno((FILE *)handle), filename, S_IFREG, modemask,
  owners, owngroups, "json", errmsg) == 0;
}



/*************************************************
*         Find entry point for lsearch           *
*************************************************/

/* See local README for interface description */

static int
json_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
FILE * f = handle;
json_t * j, * j0;
json_error_t jerr;
uschar * key;
int sep = 0;

length = length;	/* Keep picky compilers happy */
do_cache = do_cache;	/* Keep picky compilers happy */

rewind(f);
if (!(j = json_loadf(f, 0, &jerr)))
  {
  *errmsg = string_sprintf("json error on open: %.*s\n",
       JSON_ERROR_TEXT_LENGTH, jerr.text);
  return FAIL;
  }
j0 = j;

for (int k = 1;  (key = string_nextinlist(&keystring, &sep, NULL, 0)); k++)
  {
  BOOL numeric = TRUE;
  for (uschar * s = key; *s; s++) if (!isdigit(*s)) { numeric = FALSE; break; }

  if (!(j = numeric
	? json_array_get(j, (size_t) strtoul(CS key, NULL, 10))
	: json_object_get(j, CCS key)
     ) )
    {
    DEBUG(D_lookup) debug_printf_indent("%s, for key %d: '%s'\n",
      numeric
      ? US"bad index, or not json array"
      : US"no such key, or not json object",
      k, key);
    json_decref(j0);
    return FAIL;
    }
  }

switch (json_typeof(j))
  {
  case JSON_STRING:
    *result = string_copyn(CUS json_string_value(j), json_string_length(j));
    break;
  case JSON_INTEGER:
    *result = string_sprintf("%" JSON_INTEGER_FORMAT, json_integer_value(j));
    break;
  case JSON_REAL:
    *result = string_sprintf("%f", json_real_value(j));
    break;
  case JSON_TRUE:	*result = US"true";	break;
  case JSON_FALSE:	*result = US"false";	break;
  case JSON_NULL:	*result = NULL;		break;
  default:		*result = US json_dumps(j, 0); break;
  }
json_decref(j0);
return OK;
}



/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

static void
json_close(void *handle)
{
(void)fclose((FILE *)handle);
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
json_version_report(FILE *f)
{
fprintf(f, "Library version: json: Jansonn version %s\n", JANSSON_VERSION);
}


static lookup_info json_lookup_info = {
  .name = US"json",			/* lookup name */
  .type = lookup_absfile,		/* uses absolute file name */
  .open = json_open,			/* open function */
  .check = json_check,			/* check function */
  .find = json_find,			/* find function */
  .close = json_close,			/* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = json_version_report         /* version reporting */
};


#ifdef DYNLOOKUP
#define json_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &json_lookup_info };
lookup_module_info json_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/json.c */
