/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2014 */

/* This file provides TLS/SSL support for Exim using the GnuTLS library,
one of the available supported implementations.  This file is #included into
tls.c when USE_GNUTLS has been set.
*/

#include <gnutls/gnutls.h>
/* needed for cert checks in verification and DN extraction: */
#include <gnutls/x509.h>
/* needed to disable PKCS11 autoload unless requested */
#if GNUTLS_VERSION_NUMBER >= 0x020c00
# include <gnutls/pkcs11.h>
#endif


/*****************************************************
*  Export/import a certificate, binary/printable
*****************************************************/
int
tls_export_cert(uschar * buf, size_t buflen, void * cert)
{
size_t sz = buflen;
void * reset_point = store_get(0);
int fail = 0;
uschar * cp;

if (gnutls_x509_crt_export((gnutls_x509_crt_t)cert,
    GNUTLS_X509_FMT_PEM, buf, &sz))
  return 1;
if ((cp = string_printing(buf)) != buf)
  {
  Ustrncpy(buf, cp, buflen);
  if (buf[buflen-1])
    fail = 1;
  }
store_reset(reset_point);
return fail;
}

int
tls_import_cert(const uschar * buf, void ** cert)
{
void * reset_point = store_get(0);
gnutls_datum_t datum;
gnutls_x509_crt_t crt;
int fail = 0;

gnutls_global_init();
gnutls_x509_crt_init(&crt);

datum.data = string_unprinting(US buf);
datum.size = Ustrlen(datum.data);
if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_PEM))
  fail = 1;
else
  *cert = (void *)crt;

store_reset(reset_point);
return fail;
}

void
tls_free_cert(void * cert)
{
gnutls_x509_crt_deinit((gnutls_x509_crt_t) cert);
gnutls_global_deinit();
}

/*****************************************************
*  Certificate field extraction routines
*****************************************************/
static uschar *
time_copy(time_t t)
{
uschar * cp = store_get(32);
struct tm * tp = gmtime(&t);
size_t len = strftime(CS cp, 32, "%b %e %T %Y %Z", tp);
return len > 0 ? cp : NULL;
}

/**/

uschar *
tls_cert_issuer(void * cert)
{
uschar txt[256];
size_t sz = sizeof(txt);
return ( gnutls_x509_crt_get_issuer_dn(cert, CS txt, &sz) == 0 )
  ? string_copy(txt) : NULL;
}

uschar *
tls_cert_not_after(void * cert)
{
return time_copy(
  gnutls_x509_crt_get_expiration_time((gnutls_x509_crt_t)cert));
}

uschar *
tls_cert_not_before(void * cert)
{
return time_copy(
  gnutls_x509_crt_get_activation_time((gnutls_x509_crt_t)cert));
}

uschar *
tls_cert_serial_number(void * cert)
{
uschar bin[50], txt[150];
size_t sz = sizeof(bin);
uschar * sp;
uschar * dp;

if (gnutls_x509_crt_get_serial((gnutls_x509_crt_t)cert,
    bin, &sz) || sz > sizeof(bin))
  return NULL;
for(dp = txt, sp = bin; sz; dp += 2, sp++, sz--)
  sprintf(dp, "%.2x", *sp);
for(sp = txt; sp[0]=='0' && sp[1]; ) sp++;	/* leading zeroes */
return string_copy(sp);
}

uschar *
tls_cert_signature(void * cert)
{
uschar * cp1;
uschar * cp2;
uschar * cp3;
size_t len = 0;
int ret;

if ((ret = gnutls_x509_crt_get_signature((gnutls_x509_crt_t)cert, cp1, &len)) !=
	GNUTLS_E_SHORT_MEMORY_BUFFER)
  {
  fprintf(stderr, "%s: gs0 fail: %s\n", __FUNCTION__, gnutls_strerror(ret));
  return NULL;
  }

cp1 = store_get(len*4+1);

if (gnutls_x509_crt_get_signature((gnutls_x509_crt_t)cert, cp1, &len) != 0)
  {
  fprintf(stderr, "%s: gs1 fail\n", __FUNCTION__);
  return NULL;
  }

for(cp3 = cp2 = cp1+len; cp1 < cp2; cp3 += 3, cp1++)
  sprintf(cp3, "%.2x ", *cp1);
cp3[-1]= '\0';

return cp2;
}

uschar *
tls_cert_signature_algorithm(void * cert)
{
gnutls_sign_algorithm_t algo =
  gnutls_x509_crt_get_signature_algorithm((gnutls_x509_crt_t)cert);
return algo < 0 ? NULL : string_copy(gnutls_sign_get_name(algo));
}

uschar *
tls_cert_subject(void * cert)
{
static uschar txt[256];
size_t sz = sizeof(txt);
return ( gnutls_x509_crt_get_dn(cert, CS txt, &sz) == 0 )
  ? string_copy(txt) : NULL;
}

uschar *
tls_cert_version(void * cert)
{
return string_sprintf("%d", gnutls_x509_crt_get_version(cert));
}

uschar *
tls_cert_ext_by_oid(void * cert, uschar * oid, int idx)
{
uschar * cp1 = NULL;
uschar * cp2;
uschar * cp3;
size_t siz = 0;
unsigned int crit;
int ret;

ret = gnutls_x509_crt_get_extension_by_oid ((gnutls_x509_crt_t)cert,
  oid, idx, cp1, &siz, &crit);
if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
  {
  fprintf(stderr, "%s: ge0 fail: %s\n", __FUNCTION__, gnutls_strerror(ret));
  return NULL;
  }

cp1 = store_get(siz*4 + 1);

ret = gnutls_x509_crt_get_extension_by_oid ((gnutls_x509_crt_t)cert,
  oid, idx, cp1, &siz, &crit);
if (ret < 0)
  {
  fprintf(stderr, "%s: ge1 fail: %s\n", __FUNCTION__, gnutls_strerror(ret));
  return NULL;
  }

/* binary data, DER encoded */

/* just dump for now */
for(cp3 = cp2 = cp1+siz; cp1 < cp2; cp3 += 3, cp1++)
  sprintf(cp3, "%.2x ", *cp1);
cp3[-1]= '\0';

return cp2;
}

uschar *
tls_cert_subject_altname(void * cert)
{
uschar * cp = NULL;
size_t siz = 0;
unsigned int crit;
int ret;

ret = gnutls_x509_crt_get_subject_alt_name ((gnutls_x509_crt_t)cert,
  0, cp, &siz, &crit);
switch(ret)
  {
  case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
    return NULL;
  case GNUTLS_E_SHORT_MEMORY_BUFFER:
    break;
  default:
    expand_string_message = 
      string_sprintf("%s: gs0 fail: %d %s\n", __FUNCTION__,
	ret, gnutls_strerror(ret));
    return NULL;
  }

cp = store_get(siz+1);
ret = gnutls_x509_crt_get_subject_alt_name ((gnutls_x509_crt_t)cert,
  0, cp, &siz, &crit);
if (ret < 0)
  {
  expand_string_message = 
    string_sprintf("%s: gs1 fail: %d %s\n", __FUNCTION__,
      ret, gnutls_strerror(ret));
  return NULL;
  }
cp[siz] = '\0';
return cp;
}

uschar *
tls_cert_ocsp_uri(void * cert)
{
#if GNUTLS_VERSION_NUMBER >= 0x030000
gnutls_datum_t uri;
unsigned int crit;
int ret = gnutls_x509_crt_get_authority_info_access((gnutls_x509_crt_t)cert,
	0, GNUTLS_IA_OCSP_URI, &uri, &crit);

if (ret >= 0)
  return string_copyn(uri.data, uri.size);

if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
  expand_string_message = 
    string_sprintf("%s: gai fail: %d %s\n", __FUNCTION__,
      ret, gnutls_strerror(ret));

return NULL;

#else

expand_string_message = 
  string_sprintf("%s: OCSP support with GnuTLS requires version 3.0.0\n",
    __FUNCTION__);
return NULL;

#endif
}

uschar *
tls_cert_crl_uri(void * cert)
{
int ret;
uschar * cp = NULL;
size_t siz = 0;

ret = gnutls_x509_crt_get_crl_dist_points ((gnutls_x509_crt_t)cert,
  0, cp, &siz, NULL, NULL);
switch(ret)
  {
  case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
    return NULL;
  case GNUTLS_E_SHORT_MEMORY_BUFFER:
    break;
  default:
    expand_string_message = 
      string_sprintf("%s: gc0 fail: %d %s\n", __FUNCTION__,
	ret, gnutls_strerror(ret));
    return NULL;
  }

cp = store_get(siz+1);
ret = gnutls_x509_crt_get_crl_dist_points ((gnutls_x509_crt_t)cert,
  0, cp, &siz, NULL, NULL);
if (ret < 0)
  {
  expand_string_message = 
    string_sprintf("%s: gs1 fail: %d %s\n", __FUNCTION__,
      ret, gnutls_strerror(ret));
  return NULL;
  }
cp[siz] = '\0';
return cp;
}


/* vi: aw ai sw=2
*/
/* End of tlscert-gnu.c */
