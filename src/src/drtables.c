/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


#include "exim.h"

#include <string.h>

/* This module contains tables that define the lookup methods and drivers
that are actually included in the binary. Its contents are controlled by
various macros in config.h that ultimately come from Local/Makefile. They are
all described in src/EDITME. */


tree_node * lookups_tree = NULL;
unsigned lookup_list_count = 0;

/* Lists of information about which drivers are included in the exim binary. */

auth_info * auths_available= NULL;
router_info * routers_available = NULL;
transport_info * transports_available = NULL;



#ifndef MACRO_PREDEF

static gstring *
dr_show_list(gstring * g, const uschar ** list, const uschar * label,
  const uschar * class)
{
if (*list)
  {
  const uschar ** ele = list;
  g = string_fmt_append(g, "%s (%s): ", class, label);
  while (*ele) ele++;
  while (--ele >= list) g = string_fmt_append(g, " %s", *ele);
  g = string_catn(g, US"\n", 1);
  }
return g;
}

static gstring *
dr_show_supported(gstring * g,
  const uschar ** statics, const uschar ** dynamics, const uschar * class)
{
g = dr_show_list(g, statics, US"built-in", class);
g = dr_show_list(g, dynamics, US"dynamic", class);
return g;
}

gstring *
auth_show_supported(gstring * g)
{
return dr_show_supported(g, avail_static_auths, avail_dynamic_auths,
  US"Authenticators");
}

gstring *
route_show_supported(gstring * g)
{
return dr_show_supported(g, avail_static_routers, avail_dynamic_routers,
  US"Routers");
}

gstring *
transport_show_supported(gstring * g)
{
return dr_show_supported(g, avail_static_transports, avail_dynamic_transports,
  US"Transports");
}


static void
add_lookup_to_tree(lookup_info * li)
{
tree_node * new = store_get_perm(sizeof(tree_node) + Ustrlen(li->name),
							GET_UNTAINTED);
new->data.ptr = (void *)li;
Ustrcpy(new->name, li->name);
if (tree_insertnode(&lookups_tree, new))
  li->acq_num = lookup_list_count++;
else
  log_write(0, LOG_MAIN|LOG_PANIC, "Duplicate lookup name '%s'", li->name);
}


/* Add all the lookup types provided by the module */
static void
addlookupmodule(const struct lookup_module_info * lmi)
{
for (int j = 0; j < lmi->lookupcount; j++)
  add_lookup_to_tree(lmi->lookups[j]);
}



/* Hunt for the lookup with the given acquisition number */

static unsigned hunt_acq;

static void
acq_cb(uschar * name, uschar * ptr, void * ctx)
{
lookup_info * li = (lookup_info *)ptr;
if (li->acq_num == hunt_acq) *(lookup_info **)ctx = li;
}

const lookup_info *
lookup_with_acq_num(unsigned k)
{
const lookup_info * li = NULL;
hunt_acq = k;
tree_walk(lookups_tree, acq_cb, &li);
return li;
}



#ifdef LOOKUP_MODULE_DIR
static void *
mod_open(const uschar * name, const uschar * class, uschar ** errstr)
{
const uschar * path = string_sprintf(
  LOOKUP_MODULE_DIR "/%s_%s." DYNLIB_FN_EXT, name, class);
void * dl;
if (!(dl = dlopen(CS path, RTLD_NOW)))
  {
  if (errstr)
    *errstr = string_sprintf("Error loading %s: %s", name, dlerror());
  else
    (void) dlerror();		/* clear out error state */
  return NULL;
  }

/* FreeBSD nsdispatch() can trigger dlerror() errors about
_nss_cache_cycle_prevention_function; we need to clear the dlerror()
state before calling dlsym(), so that any error afterwards only comes
from dlsym().  */

(void) dlerror();
return dl;
}


/* Try to load a lookup module with the given name.

Arguments:
    name		name of the lookup
    errstr		if not NULL, place "open fail" error message here

Return: boolean success
*/

static BOOL
lookup_mod_load(const uschar * name, uschar ** errstr)
{
void * dl;
lookup_module_info * info;
const char * errormsg;

if (!(dl = mod_open(name, US"lookup", errstr)))
  return FALSE;

info = (lookup_module_info *) dlsym(dl, "_lookup_module_info");
if ((errormsg = dlerror()))
  {
  EARLY_DEBUG(D_any, "%s does not appear to be a lookup module (%s)\n", name, errormsg);
  log_write(0, LOG_MAIN|LOG_PANIC, "%s does not appear to be a lookup module (%s)", name, errormsg);
  dlclose(dl);
  return FALSE;
  }
if (info->magic != LOOKUP_MODULE_INFO_MAGIC)
  {
  EARLY_DEBUG(D_any, "Lookup module %s is not compatible with this version of Exim\n", name);
  log_write(0, LOG_MAIN|LOG_PANIC, "Lookup module %s is not compatible with this version of Exim", name);
  dlclose(dl);
  return FALSE;
  }

addlookupmodule(info);
if (debug_startup)
  { EARLY_DEBUG(D_lookup, "Loaded %q (%d lookup type%s)\n",
				    name, info->lookupcount,
				    info->lookupcount > 1 ? "s" : ""); }
else
  DEBUG(D_lookup) debug_printf_indent("Loaded module %q\n", name);

return TRUE;
}


/* Try to load a lookup module, assuming the module name is the same
as the lookup type name.  This will only work for single-method modules.
Other have to be always-load (see the RE in init_lookup_list() below).
*/

BOOL
lookup_one_mod_load(const uschar * name, uschar ** errstr)
{
if (!lookup_mod_load(name, errstr)) return FALSE;
/*XXX notify daemon? */
return TRUE;
}

#endif	/*LOOKUP_MODULE_DIR*/

/* Look at all the lookup module files and add a name from each lookup type */

gstring *
lookup_dynamic_supported(gstring * g)
{
#ifdef LOOKUP_MODULE_DIR
DIR * dd;
const pcre2_code * regex_islookupmod = regex_must_compile(
  US"^([a-z0-9]+)_lookup\\." DYNLIB_FN_EXT "$", MCS_NOFLAGS, TRUE);

if (!(dd = exim_opendir(CUS LOOKUP_MODULE_DIR)))
  g = string_cat(g, US"FAIL exim_opendir");
else
  for (struct dirent * ent; ent = readdir(dd); )
    {
    void * dl;
    uschar * errstr;

    if (  regex_match_and_setup(regex_islookupmod, US ent->d_name, 0, 0)
       && (dl = mod_open(expand_nstring[1], US"lookup", &errstr))
       )
      {
      lookup_module_info * lmi=
	(lookup_module_info *) dlsym(dl, "_lookup_module_info");

      if (  ! dlerror()
	 && lmi->magic == LOOKUP_MODULE_INFO_MAGIC
         )
	for (lookup_info ** lip = lmi->lookups;
	    lip < lmi->lookups + lmi->lookupcount; lip++)
	  g = string_fmt_append(g, " %s", (*lip)->name);

      dlclose(dl);
      }
    }
#endif	/*!LOOKUP_MODULE_DIR*/
return g;
}



misc_module_info * misc_module_list = NULL;

static void
misc_mod_add(misc_module_info * mi)
{
mi->next = misc_module_list;
misc_module_list = mi;

if (mi->init)
  {
  EARLY_DEBUG(D_any, "Module init: %q\n", mi->name);
  expand_level++;
  if (!mi->init(mi))
    EARLY_DEBUG(D_any, "module init call failed for %q\n", mi->name);
  expand_level--;
  }

if (mi->lib_vers_report)
  DEBUG(D_any) debug_printf_indent("%Y", mi->lib_vers_report(NULL));

/* EARLY_DEBUG(D_any, "added %q\n", mi->name); */
}


#ifdef LOOKUP_MODULE_DIR

/* Load a "misc" module, and add to list */

static misc_module_info *
misc_mod_load(const uschar * name, uschar ** errstr)
{
void * dl;
struct misc_module_info * mi;
const char * errormsg;

EARLY_DEBUG(D_any, "Loading module %q\n", name);
if (!(dl = mod_open(name, US"miscmod", errstr)))
  {
  if (errstr) EARLY_DEBUG(D_any, " mod_open: %s\n", *errstr);
  return NULL;
  }

mi = (struct misc_module_info *) dlsym(dl,
				    CS string_sprintf("%s_module_info", name));
if ((errormsg = dlerror()))
  {
  EARLY_DEBUG(D_any, "%s does not appear to be a '%s' module (%s)\n",
	  name, name, errormsg);
  log_write(0, LOG_MAIN|LOG_PANIC,
    "%s does not contain the expected module info symbol (%s)", name, errormsg);
  dlclose(dl);
  return NULL;
  }
if (mi->dyn_magic != MISC_MODULE_MAGIC)
  {
  EARLY_DEBUG(D_any, "Module %s is not compatible with this version of Exim\n", name);
  log_write(0, LOG_MAIN|LOG_PANIC, "Module %s is not compatible with this version of Exim", name);
  dlclose(dl);
  return FALSE;
  }

EARLY_DEBUG(D_lookup, "Loaded module %q\n", name);
misc_mod_add(mi);
return mi;
}

#endif	/*LOOKUP_MODULE_DIR*/


/* Find a "misc" module by name, if loaded.
For now use a linear search down a linked list.  If the number of
modules gets large, we might consider a tree.
*/

misc_module_info *
misc_mod_findonly(const uschar * name)
{
for (misc_module_info * mi = misc_module_list; mi; mi = mi->next)
  if (Ustrcmp(name, mi->name) == 0)
    return mi;
return NULL;
}

/* Find a "misc" module, possibly already loaded, by name. */

misc_module_info *
misc_mod_find(const uschar * name, uschar ** errstr)
{
misc_module_info * mi;
if ((mi = misc_mod_findonly(name))) return mi;
#ifdef LOOKUP_MODULE_DIR
return misc_mod_load(name, errstr);
#else
*errstr = string_sprintf("module %q not built-in, and"
	" no setting for LOOKUP_MODULE_DIR", name);
return NULL;
#endif	/*LOOKUP_MODULE_DIR*/
}


/* For any "misc" module having a connection-init routine, call it. */

int
misc_mod_conn_init(const uschar * sender_helo_name,
  const uschar * sender_host_address, const uschar ** errstr)
{
for (const misc_module_info * mi = misc_module_list; mi; mi = mi->next)
  if (mi->conn_init)
    if ((mi->conn_init) (sender_helo_name, sender_host_address, errstr) != OK)
      return FAIL;
return OK;
}

/* Ditto, smtp-reset */

void
misc_mod_smtp_reset(void)
{
for (const misc_module_info * mi = misc_module_list; mi; mi = mi->next)
  if (mi->smtp_reset)
    (mi->smtp_reset)();
}

/* Ditto, msg-init */

int
misc_mod_msg_init(void)
{
for (const misc_module_info * mi = misc_module_list; mi; mi = mi->next)
  if (mi->msg_init)
    if ((mi->msg_init)() != OK)
      return FAIL;
return OK;
}

/* Ditto, authres.  Having to sort the responses (mainly for the testsuite)
is pretty painful - maybe we should sort the modules on insertion to
the list? */

gstring *
misc_mod_authres(gstring * g)
{
typedef struct {
  const uschar * name;
  gstring *	 res;
} pref;
pref prefs[] = {
  {US"spf", NULL}, {US"dkim", NULL}, {US"dmarc", NULL}, {US"arc", NULL}
};
gstring * others = NULL;

for (const misc_module_info * mi = misc_module_list; mi; mi = mi->next)
  if (mi->authres)
    {
    pref * p;
    for (p = prefs; p < prefs + nelem(prefs); p++)
      if (Ustrcmp(p->name, mi->name) == 0) break;

    if (p) p->res = (mi->authres)(NULL);
    else   others = (mi->authres)(others);
    }

for (pref * p = prefs; p < prefs + nelem(prefs); p++)
  g = gstring_append(g, p->res);
return gstring_append(g, others);
}






void
init_lookup_list(void)
{
#ifdef LOOKUP_MODULE_DIR
DIR * dd;
int countmodules = 0;
#endif
static BOOL lookup_list_init_done = FALSE;

if (lookup_list_init_done)
  return;
lookup_list_init_done = TRUE;

for (lookup_module_info ** avi = avail_static_lookups; *avi; avi++)
  addlookupmodule(*avi);

DEBUG(D_lookup) debug_printf_indent("Total %d built-in lookups\n", lookup_list_count);


#ifdef LOOKUP_MODULE_DIR
if (!(dd = exim_opendir(CUS LOOKUP_MODULE_DIR)))
  {
  EARLY_DEBUG(D_lookup, "Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
  log_write(0, LOG_MAIN|LOG_PANIC,
	  "Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
  }
else
  {
  /* Look specifically for modules we know offer several lookup types and
  load them now, since we cannot load-on-first-use. */

  struct dirent * ent;
  const pcre2_code * regex_islookupmod = regex_must_compile(
    US"(lsearch|ldap|nis)_lookup\\." DYNLIB_FN_EXT "$", MCS_NOFLAGS, TRUE);

  EARLY_DEBUG(D_lookup, "Loading lookup modules from %s\n", LOOKUP_MODULE_DIR);
  while ((ent = readdir(dd)))
    if (regex_match_and_setup(regex_islookupmod, US ent->d_name, 0, 0))
      {
      uschar * errstr;
      if (lookup_mod_load(expand_nstring[1], &errstr))
	countmodules++;
      else
	{
	EARLY_DEBUG(D_any, "%s\n", errstr);
	log_write(0, LOG_MAIN|LOG_PANIC, "%s", errstr);
	}
      }
  closedir(dd);
  }

EARLY_DEBUG(D_lookup, "Loaded %d dynamic lookup modules\n", countmodules);
#endif
}


/* Add module info struct to the modules list for those that are
built as static */

#if !defined(DISABLE_DKIM) && (!defined(SUPPORT_DKIM) || SUPPORT_DKIM!=2)
extern misc_module_info dkim_module_info;
#endif
#if defined(EXIM_HAVE_DMARC) && EXIM_HAVE_DMARC!=2
extern misc_module_info dmarc_module_info;
#endif
#if defined(EXIM_HAVE_SPF) && EXIM_HAVE_SPF!=2
extern misc_module_info spf_module_info;
#endif
#if defined(EXPERIMENTAL_ARC) && (!defined(SUPPORT_ARC) || SUPPORT_ARC!=2)
extern misc_module_info arc_module_info;
#endif
#if defined(SUPPORT_DSCP) && SUPPORT_DSCP!=2
extern misc_module_info dscp_module_info;
#endif
#if defined(SUPPORT_PAM) && SUPPORT_PAM!=2
extern misc_module_info pam_module_info;
#endif
#if defined(EXIM_PERL) && (!defined(SUPPORT_PERL) || SUPPORT_PERL!=2)
extern misc_module_info perl_module_info;
#endif
#if defined(SUPPORT_PROXY) && SUPPORT_PROXY!=2
extern misc_module_info proxy_module_info;
#endif
#if defined(RADIUS_CONFIG_FILE) && (!defined(SUPPORT_RADIUS) || SUPPORT_RADIUS!=2)
extern misc_module_info radius_module_info;
#endif
#if defined(SUPPORT_SOCKS) && SUPPORT_SOCKS!=2
extern misc_module_info socks_module_info;
#endif
#if defined(EXPERIMENTAL_XCLIENT) && EXPERIMENTAL_XCLIENT!=2
extern misc_module_info xclient_module_info;
#endif

#if !defined(DISABLE_EXIM_FILTER) && (!defined(SUPPORT_EXIM_FILTER) || SUPPORT_EXIM_FILTER!=2)
extern misc_module_info exim_filter_module_info;
#endif
#if !defined(DISABLE_SIEVE_FILTER) && (!defined(SUPPORT_SIEVE_FILTER) || SUPPORT_SIEVE_FILTER!=2)
extern misc_module_info sieve_filter_module_info;
#endif

void
init_misc_mod_list(void)
{
static BOOL onetime = FALSE;
if (onetime) return;
onetime = TRUE;

#if !defined(DISABLE_DKIM) && (!defined(SUPPORT_DKIM) || SUPPORT_DKIM!=2)
  misc_mod_add(&dkim_module_info);
#endif
#if defined(EXIM_HAVE_SPF) && EXIM_HAVE_SPF!=2
  misc_mod_add(&spf_module_info);
#endif
#if defined(EXPERIMENTAL_ARC) && (!defined(SUPPORT_ARC) || SUPPORT_ARC!=2)
  misc_mod_add(&arc_module_info);
#endif
#if defined(EXIM_HAVE_DMARC) && EXIM_HAVE_DMARC!=2
/* dmarc depends on spf/dkim/arc so this add must go after, for the both-static case */
  misc_mod_add(&dmarc_module_info);
#endif
#if defined(SUPPORT_DSCP) && SUPPORT_DSCP!=2
  misc_mod_add(&dscp_module_info);
#endif
#if defined(SUPPORT_PAM) && SUPPORT_PAM!=2
  misc_mod_add(&pam_module_info);
#endif
#if defined(EXPERIMENTAL_XCLIENT) && EXPERIMENTAL_XCLIENT!=2
  misc_mod_add(&xclient_module_info);
#endif
#if defined(EXIM_PERL) && (!defined(SUPPORT_PERL) || SUPPORT_PERL!=2)
  misc_mod_add(&perl_module_info);
#endif
#if defined(SUPPORT_PROXY) && SUPPORT_PROXY!=2
  misc_mod_add(&proxy_module_info);
#endif
#if !defined(DISABLE_EXIM_FILTER) && (!defined(SUPPORT_EXIM_FILTER) || SUPPORT_EXIM_FILTER!=2)
  misc_mod_add(&exim_filter_module_info);
#endif
#if !defined(DISABLE_SIEVE_FILTER) && (!defined(SUPPORT_SIEVE_FILTER) || SUPPORT_SIEVE_FILTER!=2)
  misc_mod_add(&sieve_filter_module_info);
#endif
#if defined(SUPPORT_SOCKS) && SUPPORT_SOCKS!=2
  misc_mod_add(&socks_module_info);
#endif
#if defined(RADIUS_CONFIG_FILE) && (!defined(SUPPORT_RADIUS) || SUPPORT_RADIUS!=2)
  misc_mod_add(&radius_module_info);
#endif
}


#endif	/*!MACRO_PREDEF*/
/* End of drtables.c */
