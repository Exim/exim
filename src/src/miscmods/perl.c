/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 1999 - 2022 */
/* Copyright (c) 1998 Malcolm Beattie */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Modified by PH to get rid of the "na" usage, March 1999.
   Modified further by PH for general tidying for Exim 4.
   Threaded Perl support added by Stefan Traby, Nov 2002
*/


/* This Perl add-on can be distributed under the same terms as Exim itself. */
/* See the file NOTICE for conditions of use and distribution. */

#include <assert.h>

#define HINTSDB_H
#define DBFUNCTIONS_H

#include "../exim.h"

#define EXIM_TRUE TRUE
#undef TRUE

#define EXIM_FALSE FALSE
#undef FALSE

#define EXIM_DEBUG DEBUG
#undef DEBUG

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#ifndef ERRSV
#define ERRSV (GvSV(errgv))
#endif

/* Some people like very old perl versions, so avoid any build side-effects. */

#ifndef pTHX
# define pTHX
# define pTHX_
#endif
#ifndef EXTERN_C
# define EXTERN_C extern
#endif

EXTERN_C void boot_DynaLoader(pTHX_ CV *cv);


static PerlInterpreter *interp_perl = 0;

XS(xs_expand_string)
{
  dXSARGS;
  const uschar * str;
  STRLEN len;

  if (items != 1)
    croak("Usage: Exim::expand_string(string)");

  str = CUS SvPV(ST(0), len);
  str = string_copyn(str, len);
  str = expand_string(str);

  ST(0) = sv_newmortal();
  if (str != NULL)
    sv_setpv(ST(0), CCS  str);
  else if (!f.expand_string_forcedfail)
    croak("syntax error in Exim::expand_string argument: %s",
      expand_string_message);
}

XS(xs_debug_write)
{
  dXSARGS;
  STRLEN len;
  const uschar * s;
  if (items != 1)
    croak("Usage: Exim::debug_write(string)");
  s = US SvPV(ST(0), len);
  debug_printf_indent("%.*s", (int)len, s);
}

XS(xs_log_write)
{
  dXSARGS;
  STRLEN len;
  const uschar * s;
  if (items != 1)
    croak("Usage: Exim::log_write(string)");
  s = US SvPV(ST(0), len);
  log_write(0, LOG_MAIN, "%.*s", (int)len, s);
}

static void  xs_init(pTHX)
{
  char *file = __FILE__;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("Exim::expand_string", xs_expand_string, file);
  newXS("Exim::debug_write", xs_debug_write, file);
  newXS("Exim::log_write", xs_log_write, file);
}

static uschar *
init_perl(uschar *startup_code)
{
  static int argc = 1;
  static char *argv[4] = { "exim-perl" };
  SV *sv;
  STRLEN len;

  if (opt_perl_taintmode) argv[argc++] = "-T";
  argv[argc++] = "/dev/null";
  argv[argc] = 0;

  assert(sizeof(argv)/sizeof(argv[0]) > argc);

  if (interp_perl) return 0;
  interp_perl = perl_alloc();
  perl_construct(interp_perl);
  perl_parse(interp_perl, xs_init, argc, argv, 0);
  perl_run(interp_perl);
    {
    dSP;

    /*********************************************************************/
    /* These lines by PH added to make "warn" output go to the Exim log; I
    hope this doesn't break anything. */

    sv = newSVpv(
      "$SIG{__WARN__} = sub { my($s) = $_[0];"
      "$s =~ s/\\n$//;"
      "Exim::log_write($s) };", 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR|G_DISCARD|G_KEEPERR);
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) return US SvPV(ERRSV, len);
    /*********************************************************************/

    sv = newSVpv(CS startup_code, 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR|G_DISCARD|G_KEEPERR);
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) return US SvPV(ERRSV, len);

    setlocale(LC_ALL, "C");    /* In case it got changed */
    return NULL;
    }
}

#ifdef notdef
static void
cleanup_perl(void)
{
  if (!interp_perl)
    return;
  perl_destruct(interp_perl);
  perl_free(interp_perl);
  interp_perl = 0;
}
#endif

static gstring *
call_perl_cat(gstring * yield, uschar **errstrp, uschar *name, uschar **arg)
{
  dSP;
  SV *sv;
  STRLEN len;
  const uschar *str;
  int items;

  if (!interp_perl)
    {
    *errstrp = US"the Perl interpreter has not been started";
    return 0;
    }

  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  while (*arg != NULL) XPUSHs(newSVpv(CS (*arg++), 0));
  PUTBACK;
  items = perl_call_pv(CS name, G_SCALAR|G_EVAL);
  items = items;	/* stupid compiler quietening */
  SPAGAIN;
  sv = POPs;
  PUTBACK;
  if (SvTRUE(ERRSV))
    {
    *errstrp = US SvPV(ERRSV, len);
    return NULL;
    }
  if (!SvOK(sv))
    {
    *errstrp = 0;
    return NULL;
    }
  str = US SvPV(sv, len);
  yield = string_catn(yield, str, (int)len);
  FREETMPS;
  LEAVE;

  setlocale(LC_ALL, "C");    /* In case it got changed */
  return yield;
}




/******************************************************************************/
/* Module API */

static void * perl_functions[] = {
  [PERL_STARTUP] =	(void *) init_perl,
  [PERL_CAT] =		(void *) call_perl_cat,
};

misc_module_info perl_module_info =
{
  .name =		US"perl",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif

  .functions =		perl_functions,
  .functions_count =	nelem(perl_functions),
};

/* End of perl.c */
