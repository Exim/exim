/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2025 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"

#ifndef SUPPORT_I18N
# error PSL lookup requires internationalisation support
#endif


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
psl_open(const uschar * filename, uschar ** errmsg)
{
FILE * f = fopen(CCS filename, "r");
if (f) return (void *) f;
*errmsg = US strerror(errno);
return NULL;
}

static void
psl_close(void * handle)
{
(void) fclose(handle);
}




/*************************************************
*         Generic "find" implementation          *
*************************************************/

static int
psl_gen_find(void * handle, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, BOOL is_regdom)
{
uschar rulebuf[128], * res = NULL;
const uschar * s, * k, * kmatch = NULL;
unsigned res_label_cnt = 0, nlabels;
BOOL key_utf8;

/* Ensure key is punycode and lowercase */

if ((key_utf8 = string_is_utf8(keystring)))
  {
  DEBUG(D_lookup) debug_printf_indent("converting utf8 key %q\n", keystring);
  if (!(keystring = string_domain_utf8_to_alabel(keystring, errmsg)))
    return FAIL;
  length = Ustrlen(keystring);
  DEBUG(D_lookup) debug_printf_indent(" result %q\n", keystring);
  }
else
  for (k = keystring; *k; k++)
    if (isupper(*k)) { keystring = string_copylc(keystring); break; }

while ((s = US fgets(CS rulebuf, sizeof(rulebuf), handle)))
  {
  const uschar * r;

  if (!*s || *s == '\n') continue;		/* empty line */
  if (s[0] == '/' && s[1] == '/') continue;	/* comment line */

  nlabels = 1;
  if ((r = US strsep(CSS &s, " \n\t")))
    {
    BOOL exception = *r == '!';
    const uschar * t;

    /* We convert any utf8 to punycode before starting comparison. It might
    be more efficient to wait until hitting a top-bit-set byte? */
    if (!(t = string_domain_utf8_to_alabel(r, errmsg)))
      goto fail;
    if (t != r)
      {
      DEBUG(D_lookup) debug_printf_indent("converting utf8 psl entry %q\n"
	" result %q\n", r, t);
      r = t;
      }

    for (s = r + Ustrlen(r), k = keystring + length; ; )
      {
      uschar rch = s[-1];

      if (rch == '.')		/* label separator */
	nlabels++;
      if (rch == '*')		/* wildcard in rule (assume leading) */
	{
	/* take the current label from the key */
	while (k > keystring && k[-1] != '.')
	  k--;
	s = k;
	/* s is the match */
	/* k is the key trail after the regdom. label */
	/* nlabels describes k */
	break;			/* - match */
	}
      if (rch == '!')		/* exception rule */
	{
	if (!is_regdom)
	  /* Remove the LH label then treat as a match */
	  while (TRUE)
	    if (!*s || *s++ == '.') break;

	/* s is the match, or the regdom */
	/* nlabels don't care */
	res = string_copy_taint(s, GET_UNTAINTED);
	goto found;		/* ER's have priority; stop reading file */
	}

      s--; k--;

      if (rch != *k)		/* character difference */
	goto nonmatch;
      if (k <= keystring && !exception)	/* ran out of key */
	goto nonmatch;
      if (s == r)		/* run out of rule */
	if (k[-1] != '.')	/* key has prefix on rule */
	  goto nonmatch;
	else
	  break;		/* out of rule: s is the match */
      }

    if (nlabels > res_label_cnt)
      {				/* new longest match (by cnt of labels) */
      res = string_copy_taint(s, GET_UNTAINTED);
      res_label_cnt = nlabels;
      kmatch = k;
      }

    nonmatch: ;
    }
  }
    /* kmatch is the key trail after the regdom. label */
    /* res_label_cnt describes kmatch */

if (is_regdom && res)		/* prepend label from key to pub-suffix */
  {
  s = kmatch;
  /* back up one label in key */
  if (s-- <= keystring) goto fail;	/* there must ba a dot */
  if (s-- <= keystring) goto fail;	/* there must ba at least one ch */
  while (s > keystring && s[-1] != '.') s--;
  res = string_sprintf("%.*s%s", (int)(kmatch - s), s, res);
  }

found:

if (key_utf8 && res)
  {
  if (!(*result = string_domain_alabel_to_utf8(res, errmsg)))
    goto fail;
  DEBUG(D_lookup)
    debug_printf_indent("utf8 converting result %q\n to %q\n", res, *result);
  }
else
  *result = res;

rewind(handle);
return OK;

fail:
rewind(handle);
return FAIL;
}



/*************************************************
*  Find entry points for pub-suffix and regdom   *
*************************************************/

/* See local README for interface description */

static int
psl_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
return psl_gen_find(handle, keystring, length, result, errmsg, FALSE);
}

static int
regdom_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
return psl_gen_find(handle, keystring, length, result, errmsg, TRUE);
}




/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
psl_version_report(gstring * g)
{
return string_fmt_append(g, "Library version: psl: Exim %s builtin\n",
				EXIM_VERSION_STR);
}

static lookup_info psl_lookup_info = {
  .name =	US"psl",		/* lookup name */
  .type =	lookup_absfile,		/* lookup from file */
  .open =	psl_open,		/* open function */
  .check =	NULL,			/* no check function */
  .find =	psl_find,		/* find function */
  .close =	psl_close,		/* close function */
  .tidy =	NULL,			/* no tidy function */
  .quote =	NULL,			/* no quoting function */
  .version_report = psl_version_report	/* version reporting */
};

static lookup_info regdom_lookup_info = {
  .name =	US"regdom",		/* lookup name */
  .type =	lookup_absfile,		/* lookup from file */
  .open =	psl_open,		/* open function */
  .check =	NULL,			/* no check function */
  .find =	regdom_find,		/* find function */
  .close =	psl_close,		/* close function */
  .tidy =	NULL,			/* no tidy function */
  .quote =	NULL,			/* no quoting function */
  .version_report = NULL		/* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define psl_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &psl_lookup_info, &regdom_lookup_info };
lookup_module_info psl_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 2 };

/* End of lookups/psl.c */
