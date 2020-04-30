/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"

#include <rpcsvc/ypclnt.h>


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. This serves for both
the "nis" and "nis0" lookup types. */

static void *
nis_open(const uschar * filename, uschar ** errmsg)
{
char *nis_domain;
if (yp_get_default_domain(&nis_domain) != 0)
  {
  *errmsg = US"failed to get default NIS domain";
  return NULL;
  }
return nis_domain;
}



/*************************************************
*           Find entry point for nis             *
*************************************************/

/* See local README for interface description. A separate function is used
for nis0 because they are so short it isn't worth trying to use any common
code. */

static int
nis_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
int rc;
uschar *nis_data;
int nis_data_length;
do_cache = do_cache;   /* Placate picky compilers */
if ((rc = yp_match(CCS handle, CCS filename, CCS keystring, length,
    CSS &nis_data, &nis_data_length)) == 0)
  {
  *result = string_copy(nis_data);
  (*result)[nis_data_length] = 0;    /* remove final '\n' */
  return OK;
  }
return (rc == YPERR_KEY || rc == YPERR_MAP)? FAIL : DEFER;
}



/*************************************************
*           Find entry point for nis0            *
*************************************************/

/* See local README for interface description. */

static int
nis0_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
int rc;
uschar *nis_data;
int nis_data_length;
do_cache = do_cache;   /* Placate picky compilers */
if ((rc = yp_match(CCS handle, CCS filename, CCS keystring, length + 1,
    CSS &nis_data, &nis_data_length)) == 0)
  {
  *result = string_copy(nis_data);
  (*result)[nis_data_length] = 0;    /* remove final '\n' */
  return OK;
  }
return (rc == YPERR_KEY || rc == YPERR_MAP)? FAIL : DEFER;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
nis_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: NIS: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info nis_lookup_info = {
  .name = US"nis",			/* lookup name */
  .type = 0,				/* not abs file, not query style*/
  .open = nis_open,			/* open function */
  .check = NULL,			/* check function */
  .find = nis_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = nis_version_report             /* version reporting */
};

static lookup_info nis0_lookup_info = {
  .name = US"nis0",			/* lookup name */
  .type = 0,				/* not absfile, not query style */
  .open = nis_open,			/* sic */         /* open function */
  .check = NULL,			/* check function */
  .find = nis0_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = NULL                           /* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define nis_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &nis_lookup_info, &nis0_lookup_info };
lookup_module_info nis_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 2 };

/* End of lookups/nis.c */
