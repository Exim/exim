/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 1999 - 2025 */
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
# define ERRSV (GvSV(errgv))
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

/******************************************************************************/

/*API: Add a block of perl code to the interpreter.
Return NULL for success, else an error string.
*/

static uschar *
exim_perl_add_codeblock(const uschar * code)
{
dSP;
SV * sv;
uschar * s = NULL;

expand_level++;
/* debug_printf_indent("%s %d: %.20s...\n", __FUNCTION__, __LINE__, code); */

sv = newSVpv(CCS code, 0);
PUSHMARK(SP);
perl_eval_sv(sv, G_SCALAR|G_DISCARD|G_KEEPERR);
SvREFCNT_dec(sv);

if (SvTRUE(ERRSV))
  {				/* error return */
  STRLEN len;
  s = US SvPV(ERRSV, len);
  s = string_copyn(s, (unsigned)len);
  }

setlocale(LC_ALL, "C");		/* In case it got changed */
expand_level--;
return s;
}

/******************************************************************************/

static PerlInterpreter * interp_perl = NULL;

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
if (str)
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

/* Do a DNS lookup using Exim's facilities.  Returns a scalar with the response packet. */

XS(xs_dns_lookup)
{
dXSARGS;
STRLEN len;
const uschar * domain;
int rrtype_int, dns_res;
dns_answer * dnsa = store_get_dns_answer();

if (items != 2)
  croak("Usage: Exim_dns_lookup(name, rrtype)");
domain = CUS SvPV(ST(0), len);
domain = string_copyn(domain, (unsigned)len);
rrtype_int = (int) SvIV(ST(1));

dns_res = dns_lookup(dnsa, domain, rrtype_int, NULL);
/*
debug_printf_indent("perl dns res: %s\n", dns_rc_names[dns_res]);
debug_printf_indent(" dnsa answer %p len %d\n", dnsa->answer, dnsa->answerlen);
*/

ST(0) = sv_newmortal();
sv_setpvn(ST(0), CCS dnsa->answer,
		  (STRLEN) (dns_res == DNS_NODATA ? 0 : dnsa->answerlen));
XSRETURN(1);	/* ? needed because there are 2 arg, but 1 res? */

store_free_dns_answer(dnsa);
}

static void
xs_init(pTHX)
{
char * file = __FILE__;
newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
newXS("Exim::expand_string", xs_expand_string, file);
newXS("Exim::debug_write", xs_debug_write, file);
newXS("Exim::log_write", xs_log_write, file);
newXS("Exim::dns_lookup", xs_dns_lookup, file);
}



/*API: Start the perl interpreter and load the given block of code */

static uschar *
exim_perl_init(const uschar * startup_code)
{
static int argc = 1;
static char * argv[4] = { "exim-perl" };
uschar * errstr;

if (opt_perl_taintmode) argv[argc++] = "-T";
argv[argc++] = "/dev/null";
argv[argc] = 0;

assert(sizeof(argv)/sizeof(argv[0]) > argc);

if (interp_perl) return NULL;
interp_perl = perl_alloc();
perl_construct(interp_perl);
perl_parse(interp_perl, xs_init, argc, argv, 0);
perl_run(interp_perl);

/*********************************************************************/
/* These lines by PH added to make "warn" output go to the Exim log; I
hope this doesn't break anything. */

errstr = exim_perl_add_codeblock(US
  "$SIG{__WARN__} = sub { my($s) = $_[0];"
  "$s =~ s/\\n$//;"
  "Exim::log_write($s) };"

/* These lines added by JGH to route DNS queries via Exim's facilities */

  "package Net::DNS::Resolver;"
  "sub send {"
        "my ( $self, $dom, $rrtype_str ) = @_;"
	"my $rr = {"
	"\"A\"     => 1,"
	"\"NS\"    => 2,"
	"\"CNAME\" => 5,"
	"\"SOA\"   => 6,"
	"\"PTR\"   => 12,"
	"\"MX\"    => 15,"
	"\"TXT\"   => 16,"
	"\"AAAA\"  => 28,"
	"\"SRV\"   => 33,"
	"\"TLSA\"  => 52,"
	"\"SPF\"   => 99,"
	"};"
	"my $rrtype = $rr->{$rrtype_str};"		/*XXX only one rrtype per query...*/
        "my $dnsa = Exim::dns_lookup($dom, $rrtype);"
	"my $res = Net::DNS::Packet->decode( \\$dnsa );"
		/* "Exim::debug_write( $res->string . '\n' );" */
	"return $res;"
  "}"
  "package MAIN;"
  );

if (!errstr)
  errstr = exim_perl_add_codeblock(startup_code);

return errstr;
}

#ifdef notdef
static void
exim_cleanup_perl(void)
{
if (!interp_perl)
  return;
perl_destruct(interp_perl);
perl_free(interp_perl);
interp_perl = 0;
}
#endif



/*API: call a perl function, appending its (scalar) result to the current
yield string */

static gstring *
call_perl_cat(gstring * yield, uschar ** errstrp,
  uschar * name, const uschar ** arg)
{
dSP;
SV * sv;
STRLEN len;
const uschar * str;
int items;

if (!interp_perl)
  {
  *errstrp = US"the Perl interpreter has not been started";
  return 0;
  }

ENTER;
SAVETMPS;
PUSHMARK(SP);
while (*arg) XPUSHs(newSVpv(CCS (*arg++), 0));
PUTBACK;
items = perl_call_pv(CS name, G_SCALAR|G_EVAL);
items = items;	/* stupid compiler quietening */
SPAGAIN;
sv = POPs;
PUTBACK;
if (SvTRUE(ERRSV))
  {
  *errstrp = US SvPV(ERRSV, len);
  *errstrp = string_copyn(*errstrp, (unsigned)len);
  return NULL;
  }
if (!SvOK(sv))
  {
  *errstrp = NULL;
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
  [PERL_STARTUP] =	(void *) exim_perl_init,
  [PERL_CAT] =		(void *) call_perl_cat,
  [PERL_ADDBLOCK] =	(void *) exim_perl_add_codeblock,
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
