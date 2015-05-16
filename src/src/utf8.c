/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2015 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"

#ifdef EXPERIMENTAL_INTERNATIONAL

#include <idna.h>
#include <punycode.h>
#include <stringprep.h>

BOOL
string_is_utf8(const uschar * s)
{
uschar c;
while ((c = *s++)) if (c & 0x80) return TRUE;
return FALSE;
}

/**************************************************/
/* Domain conversions */
/* the *err string pointer should be null before the call */

uschar *
string_domain_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
uschar * s1;
uschar * s;
int rc;

s = US stringprep_utf8_nfkc_normalize(CCS utf8, -1);
if (  (rc = idna_to_ascii_8z(CCS s, CSS &s1, IDNA_ALLOW_UNASSIGNED))
   != IDNA_SUCCESS)
  {
  free(s);
  if (err) *err = US idna_strerror(rc);
  return NULL;
  }
free(s);
s = string_copy(s1);
free(s1);
return s;
}



uschar *
string_domain_alabel_to_utf8(const uschar * alabel, uschar ** err)
{
uschar * s1;
uschar * s;
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
}

/**************************************************/
/* localpart conversions */
/* the *err string pointer should be null before the call */


uschar *
string_localpart_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
size_t ucs4_len;
punycode_uint * p;
size_t p_len;
uschar * res;
int rc;

if (!string_is_utf8(utf8)) return string_copy(utf8);

p = (punycode_uint *) stringprep_utf8_to_ucs4(CCS utf8, -1, &ucs4_len);
p_len = ucs4_len*4;	/* this multiplier is pure guesswork */
res = store_get(p_len+5);

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


uschar *
string_localpart_alabel_to_utf8(const uschar * alabel, uschar ** err)
{
size_t p_len = Ustrlen(alabel);
punycode_uint * p;
uschar * s;
uschar * res;
int rc;

if (alabel[0] != 'x' || alabel[1] != 'n' || alabel[2] != '-' || alabel[3] != '-')
  {
  if (err) *err = US"bad alabel prefix";
  return NULL;
  }

p_len -= 4;
p = (punycode_uint *) store_get((p_len+1) * sizeof(*p));

if ((rc = punycode_decode(p_len, CCS alabel+4, &p_len, p, NULL)) != PUNYCODE_SUCCESS)
  {
  if (err) *err = US punycode_strerror(rc);
  return NULL;
  }

s = stringprep_ucs4_to_utf8(p, p_len, NULL, &p_len);
res = string_copyn(s, p_len);
free(s);
return res;
}


/**************************************************/
/* whole address conversion */
/* the *err string pointer should be null before the call */

uschar *
string_address_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
const uschar * s;
uschar * l;
uschar * d;

if (!*utf8) return string_copy(utf8);

DEBUG(D_expand) debug_printf("addr from utf8 <%s>", utf8);

for (s = utf8; *s; s++)
  if (*s == '@')
    {
    l = string_copyn(utf8, s - utf8);
    if (  (l = string_localpart_utf8_to_alabel(l, err), err && *err)
       || (d = string_domain_utf8_to_alabel(++s, err),  err && *err)
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

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
utf8_version_report(FILE *f)
{
fprintf(f, "Library version: IDN: Compile: %s\n"
           "                      Runtime: %s\n",
	STRINGPREP_VERSION,
	stringprep_check_version(NULL));
}

#endif	/* whole file */

/* vi: aw ai sw=2
*/
/* End of utf8.c */
