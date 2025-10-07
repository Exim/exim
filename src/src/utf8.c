/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2022 */
/* Copyright (c) Jeremy Harris 2015 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


#include "exim.h"

#ifdef SUPPORT_I18N

#ifdef SUPPORT_I18N_2008
# include <idn2.h>
#else
# include <idna.h>
#endif

#include <punycode.h>
#include <stringprep.h>

static uschar *
string_localpart_alabel_to_utf8_(const uschar * alabel, uschar ** err);

/**************************************************/

BOOL
string_is_utf8(const uschar * s)
{
uschar c;
if (s) while ((c = *s++)) if (c & 0x80) return TRUE;
return FALSE;
}

static BOOL
string_is_alabel(const uschar * s)
{
return s[0] == 'x' && s[1] == 'n' && s[2] == '-' && s[3] == '-';
}

/**************************************************/
/* Domain conversions.
The *err string pointer should be null before the call

Return NULL for error, with optional errstr pointer filled in
*/

const uschar *
string_domain_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
const uschar * cs;
uschar * t, * s;
int rc;

#ifdef SUPPORT_I18N_2008
/* Avoid lowercasing plain-ascii domains */
if (!string_is_utf8(utf8))
  return string_copy(utf8);

/* Only lowercase is accepted by the library call.  A pity since we lose
any mixed-case annotation.  This does not really matter for a domain. */
  {
  const uschar * cs1;
  uschar c;
  for (cs1 = cs = utf8; (c = *cs1); cs1++) if (!(c & 0x80) && isupper(c))
    {
    s = string_copy(utf8);
    for (t = s + (cs1 - utf8); (c = *t); t++) if (!(c & 0x80) && isupper(c))
      *t = tolower(c);
    cs = s;
    break;
    }
  }
if ((rc = idn2_lookup_u8((const uint8_t *) cs, &t, IDN2_NFC_INPUT)) != IDN2_OK)
  {
  if (err) *err = US idn2_strerror(rc);
  return NULL;
  }
#else
s = US stringprep_utf8_nfkc_normalize(CCS utf8, -1);
if (  (rc = idna_to_ascii_8z(CCS s, CSS &t, IDNA_ALLOW_UNASSIGNED))
   != IDNA_SUCCESS)
  {
  free(s);
  if (err) *err = US idna_strerror(rc);
  return NULL;
  }
free(s);
#endif
cs = string_copy(t);
free(t);
return cs;
}



uschar *
string_domain_alabel_to_utf8(const uschar * alabel, uschar ** err)
{
#ifdef SUPPORT_I18N_2008
const uschar * label;
int sep = '.';
gstring * g = NULL;

while (label = string_nextinlist(&alabel, &sep, NULL, 0))
  if (  string_is_alabel(label)
     && !(label = string_localpart_alabel_to_utf8_(label, err))
     )
    return NULL;
  else
    g = string_append_listele(g, '.', label);
return string_from_gstring(g);

#else

uschar * s1, * s;
int rc;

if (  (rc = idna_to_unicode_8z8z(CCS alabel, CSS &s1, IDNA_USE_STD3_ASCII_RULES))
   != IDNA_SUCCESS)
  {
  if (err) *err = US idna_strerror(rc);
  return NULL;
  }
s = string_copy(s1);
free(s1);
return s;
#endif
}

/**************************************************/
/* localpart conversions */
/* the *err string pointer should be null before the call */


const uschar *
string_localpart_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
size_t ucs4_len = 0;
punycode_uint * p;
size_t p_len;
uschar * res;
int rc;

if (!string_is_utf8(utf8)) return string_copy(utf8);

p = (punycode_uint *) stringprep_utf8_to_ucs4(CCS utf8, -1, &ucs4_len);
if (!p || !ucs4_len)
  {
  if (err) *err = US"l_u2a: bad UTF-8 input";
  return NULL;
  }
p_len = ucs4_len*4;	/* this multiplier is pure guesswork */
res = store_get(p_len+5, utf8);

res[0] = 'x'; res[1] = 'n'; res[2] = res[3] = '-';

if ((rc = punycode_encode(ucs4_len, p, NULL, &p_len, CS res+4)) != PUNYCODE_SUCCESS)
  {
  DEBUG(D_expand) debug_printf("l_u2a: bad '%s'\n", punycode_strerror(rc));
  free(p);
  if (err) *err = US punycode_strerror(rc);
  return NULL;
  }
p_len += 4;
free(p);
res[p_len] = '\0';
return res;
}


static uschar *
string_localpart_alabel_to_utf8_(const uschar * alabel, uschar ** err)
{
size_t p_len;
punycode_uint * p;
int rc;
uschar * s, * res;

DEBUG(D_expand) debug_printf("l_a2u: '%s'\n", alabel);
alabel += 4;
p_len = Ustrlen(alabel);
p = store_get((p_len+1) * sizeof(*p), alabel);

if ((rc = punycode_decode(p_len, CCS alabel, &p_len, p, NULL)) != PUNYCODE_SUCCESS)
  {
  if (err) *err = US punycode_strerror(rc);
  return NULL;
  }

s = US stringprep_ucs4_to_utf8(p, p_len, NULL, &p_len);
res = string_copyn(s, p_len);
free(s);
return res;
}


uschar *
string_localpart_alabel_to_utf8(const uschar * alabel, uschar ** err)
{
if (string_is_alabel(alabel))
  return string_localpart_alabel_to_utf8_(alabel, err);

if (err) *err = US"bad alabel prefix";
return NULL;
}


/**************************************************/
/* Whole address conversion.
The *err string pointer should be null before the call.

Return NULL on error, with (optional) errstring pointer filled in
*/

const uschar *
string_address_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
const uschar * l, * d;

if (!*utf8) return string_copy(utf8);

DEBUG(D_expand) debug_printf("addr from utf8 <%s>", utf8);

for (const uschar * s = utf8; *s; s++)
  if (*s == '@')
    {
    l = string_copyn(utf8, s - utf8);
    if (  !(l = string_localpart_utf8_to_alabel(l, err))
       || !(d = string_domain_utf8_to_alabel(++s, err))
       )
      return NULL;
    l = string_sprintf("%s@%s", l, d);
    DEBUG(D_expand) debug_printf(" -> <%s>\n", l);
    return l;
    }

l =  string_localpart_utf8_to_alabel(utf8, err);
DEBUG(D_expand) debug_printf(" -> <%s>\n", l);
return l;
}



/*************************************************
*         Report the library versions.           *
*************************************************/

/* See a description in tls-openssl.c for an explanation of why this exists.

Arguments:   string to append to
Returns:     string
*/

gstring *
utf8_version_report(gstring * g)
{
#ifdef SUPPORT_I18N_2008
g = string_fmt_append(g, "Library version: IDN2: Compile: %s\n"
           "                       Runtime: %s\n",
	IDN2_VERSION,
	idn2_check_version(NULL));
g = string_fmt_append(g, "Library version: Stringprep: Compile: %s\n"
           "                             Runtime: %s\n",
	STRINGPREP_VERSION,
	stringprep_check_version(NULL));
#else
g = string_fmt_append(g, "Library version: IDN: Compile: %s\n"
           "                      Runtime: %s\n",
	STRINGPREP_VERSION,
	stringprep_check_version(NULL));
#endif
return g;
}

#endif	/* whole file */

/* vi: aw ai sw=2
*/
/* End of utf8.c */
