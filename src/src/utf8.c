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

uschar *
string_domain_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
uschar * s1;
uschar * s;
int rc;

s = US stringprep_utf8_nfkc_normalize(CCS utf8, -1);
if (  (rc = idna_to_ascii_8z(CCS s, CSS &s1, IDNA_USE_STD3_ASCII_RULES))
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


uschar *
string_localpart_utf8_to_alabel(const uschar * utf8, uschar ** err)
{
size_t ucs4_len;
punycode_uint * p = (punycode_uint *) stringprep_utf8_to_ucs4(CCS utf8, -1, &ucs4_len);
size_t p_len = ucs4_len*4;	/* this multiplier is pure guesswork */
uschar * res = store_get(p_len+5);
int rc;

res[0] = 'x'; res[1] = 'n'; res[2] = res[3] = '-';

if ((rc = punycode_encode(ucs4_len, p, NULL, &p_len, res+4)) != PUNYCODE_SUCCESS)
  {
  free(p);
  if (err) *err = US punycode_strerror(rc);
  return NULL;
  }
free(p);
res[p_len] = '\0';
return res;
}


uschar *
string_localpart_alabel_to_utf8(const uschar * alabel, uschar ** err)
{
size_t p_len = strlen(alabel);
punycode_uint * p;
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
p[p_len] = 0;
return US p;
}


#endif	/* whole file */

/* vi: aw ai sw=2
*/
/* End of utf8.c */
