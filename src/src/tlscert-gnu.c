/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2021 - 2022 */
/* Copyright (c) Jeremy Harris 2014 - 2018 */
/* SPDX-License-Identifier: GPL-2.0-or-later */

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
******************************************************
Return: boolean success
*/

BOOL
tls_export_cert(uschar * buf, size_t buflen, void * cert)
{
size_t sz = buflen;
rmark reset_point = store_mark();
BOOL fail;
const uschar * cp;

if ((fail = gnutls_x509_crt_export((gnutls_x509_crt_t)cert,
    GNUTLS_X509_FMT_PEM, buf, &sz)))
  {
  log_write(0, LOG_MAIN, "TLS error in certificate export: %s",
    gnutls_strerror(fail));
  return FALSE;
  }
if ((cp = string_printing(buf)) != buf)
  {
  Ustrncpy(buf, cp, buflen);
  if (buf[buflen-1])
    fail = 1;
  }
store_reset(reset_point);
return !fail;
}

/* On error, NULL out the destination */
BOOL
tls_import_cert(const uschar * buf, void ** cert)
{
rmark reset_point = store_mark();
gnutls_datum_t datum;
gnutls_x509_crt_t crt = *(gnutls_x509_crt_t *)cert;
int rc;

if (crt)
  gnutls_x509_crt_deinit(crt);
else
  gnutls_global_init();

gnutls_x509_crt_init(&crt);

datum.data = string_unprinting(US buf);
datum.size = Ustrlen(datum.data);
if ((rc = gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_PEM)))
  {
  log_write(0, LOG_MAIN, "TLS error in certificate import: %s",
    gnutls_strerror(rc));
  crt = NULL;
  }
*cert = (void *)crt;
store_reset(reset_point);
return rc != 0;
}

void
tls_free_cert(void ** cert)
{
gnutls_x509_crt_t crt = *(gnutls_x509_crt_t *)cert;
if (crt)
  {
  gnutls_x509_crt_deinit(crt);
  gnutls_global_deinit();
  *cert = NULL;
  }
}

/*****************************************************
*  Certificate field extraction routines
*****************************************************/

/* First, some internal service functions */

static uschar *
g_err(const char * tag, const char * from, int gnutls_err)
{
expand_string_message = string_sprintf("%s: %s fail: %s\n",
  from, tag, gnutls_strerror(gnutls_err));
return NULL;
}


static uschar *
time_copy(time_t t, const uschar * mod)
{
uschar * cp;
size_t len = 32;

if (mod && Ustrcmp(mod, "int") == 0)
  return string_sprintf("%u", (unsigned)t);

cp = store_get(len, GET_UNTAINTED);
if (f.timestamps_utc)
  {
  uschar * tz = to_tz(US"GMT0");
  len = strftime(CS cp, len, "%b %e %T %Y %Z", gmtime(&t));
  restore_tz(tz);
  }
else
  len = strftime(CS cp, len, "%b %e %T %Y %Z", localtime(&t));
return len > 0 ? cp : NULL;
}


/**/
/* Now the extractors, called from expand.c
Arguments:
  cert		The certificate
  mod		Optional modifiers for the operator

Return:
  Allocated string with extracted value
*/

uschar *
tls_cert_issuer(void * cert, const uschar * mod)
{
uschar * cp = NULL;
int ret;
size_t siz = 0;

if ((ret = gnutls_x509_crt_get_issuer_dn(cert, CS cp, &siz))
    != GNUTLS_E_SHORT_MEMORY_BUFFER)
  return g_err("gi0", __FUNCTION__, ret);

cp = store_get(siz, GET_TAINTED);
if ((ret = gnutls_x509_crt_get_issuer_dn(cert, CS cp, &siz)) < 0)
  return g_err("gi1", __FUNCTION__, ret);

return mod ? tls_field_from_dn(cp, mod) : cp;
}

uschar *
tls_cert_not_after(void * cert, const uschar * mod)
{
return time_copy(
  gnutls_x509_crt_get_expiration_time((gnutls_x509_crt_t)cert),
  mod);
}

uschar *
tls_cert_not_before(void * cert, const uschar * mod)
{
return time_copy(
  gnutls_x509_crt_get_activation_time((gnutls_x509_crt_t)cert),
  mod);
}

uschar *
tls_cert_serial_number(void * cert, const uschar * mod)
{
uschar bin[50], txt[150];
uschar * sp = bin;
size_t sz = sizeof(bin);
int ret;

if ((ret = gnutls_x509_crt_get_serial((gnutls_x509_crt_t)cert,
    bin, &sz)))
  return g_err("gs0", __FUNCTION__, ret);

for(uschar * dp = txt; sz; sz--)
  dp += sprintf(CS dp, "%.2x", *sp++);
for(sp = txt; sp[0]=='0' && sp[1]; ) sp++;	/* leading zeroes */
return string_copy(sp);
}

uschar *
tls_cert_signature(void * cert, const uschar * mod)
{
uschar * cp1 = NULL;
uschar * cp2;
uschar * cp3;
size_t len = 0;
int ret;

if ((ret = gnutls_x509_crt_get_signature((gnutls_x509_crt_t)cert, CS cp1, &len))
    != GNUTLS_E_SHORT_MEMORY_BUFFER)
  return g_err("gs0", __FUNCTION__, ret);

cp1 = store_get(len*4+1, GET_TAINTED);
if (gnutls_x509_crt_get_signature((gnutls_x509_crt_t)cert, CS cp1, &len) != 0)
  return g_err("gs1", __FUNCTION__, ret);

for(cp3 = cp2 = cp1+len; cp1 < cp2; cp1++)
  cp3 += sprintf(CS cp3, "%.2x ", *cp1);
cp3[-1]= '\0';

return cp2;
}

uschar *
tls_cert_signature_algorithm(void * cert, const uschar * mod)
{
gnutls_sign_algorithm_t algo =
  gnutls_x509_crt_get_signature_algorithm((gnutls_x509_crt_t)cert);
return algo < 0 ? NULL : string_copy(US gnutls_sign_get_name(algo));
}

uschar *
tls_cert_subject(void * cert, const uschar * mod)
{
uschar * cp = NULL;
int ret;
size_t siz = 0;

if ((ret = gnutls_x509_crt_get_dn(cert, CS cp, &siz))
    != GNUTLS_E_SHORT_MEMORY_BUFFER)
  return g_err("gs0", __FUNCTION__, ret);

cp = store_get(siz, GET_TAINTED);
if ((ret = gnutls_x509_crt_get_dn(cert, CS cp, &siz)) < 0)
  return g_err("gs1", __FUNCTION__, ret);

return mod ? tls_field_from_dn(cp, mod) : cp;
}

uschar *
tls_cert_version(void * cert, const uschar * mod)
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
  CS oid, idx, CS cp1, &siz, &crit);
if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
  return g_err("ge0", __FUNCTION__, ret);

cp1 = store_get(siz*4 + 1, GET_TAINTED);

ret = gnutls_x509_crt_get_extension_by_oid ((gnutls_x509_crt_t)cert,
  CS oid, idx, CS cp1, &siz, &crit);
if (ret < 0)
  return g_err("ge1", __FUNCTION__, ret);

/* binary data, DER encoded */

/* just dump for now */
for(cp3 = cp2 = cp1+siz; cp1 < cp2; cp1++)
  cp3 += sprintf(CS cp3, "%.2x ", *cp1);
cp3[-1]= '\0';

return cp2;
}

uschar *
tls_cert_subject_altname(void * cert, const uschar * mod)
{
gstring * list = NULL;
size_t siz;
int ret;
uschar sep = '\n';
uschar * tag = US"", * ele;
int match = -1;

if (mod) while (*mod)
  {
  if (*mod == '>' && *++mod) sep = *mod++;
  else if (Ustrncmp(mod, "dns", 3)==0) { match = GNUTLS_SAN_DNSNAME; mod += 3; }
  else if (Ustrncmp(mod, "uri", 3)==0) { match = GNUTLS_SAN_URI; mod += 3; }
  else if (Ustrncmp(mod, "mail", 4)==0) { match = GNUTLS_SAN_RFC822NAME; mod += 4; }
  else break;

  if (*mod++ != ',')
    break;
  }

for (int index = 0;; index++)
  {
  siz = 0;
  switch(ret = gnutls_x509_crt_get_subject_alt_name(
      (gnutls_x509_crt_t)cert, index, NULL, &siz, NULL))
    {
    case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
      return string_from_gstring(list);	/* no more elements; normal exit */

    case GNUTLS_E_SHORT_MEMORY_BUFFER:
      break;

    default:
      return g_err("gs0", __FUNCTION__, ret);
    }

  ele = store_get(siz+1, GET_TAINTED);
  if ((ret = gnutls_x509_crt_get_subject_alt_name(
    (gnutls_x509_crt_t)cert, index, ele, &siz, NULL)) < 0)
    return g_err("gs1", __FUNCTION__, ret);
  ele[siz] = '\0';

  if (  match != -1 && match != ret	/* wrong type of SAN */
     || Ustrlen(ele) != siz)		/* contains a NUL */
    continue;
  switch (ret)
    {
    case GNUTLS_SAN_DNSNAME:    tag = US"DNS";  break;
    case GNUTLS_SAN_URI:        tag = US"URI";  break;
    case GNUTLS_SAN_RFC822NAME: tag = US"MAIL"; break;
    default: continue;        /* ignore unrecognised types */
    }
  list = match == -1
    ? string_append_listele_fmt(list, sep, TRUE, "%s=%s", tag, ele)
    : string_append_listele(list, sep, ele);
  }
/*NOTREACHED*/
}

uschar *
tls_cert_ocsp_uri(void * cert, const uschar * mod)
{
#if GNUTLS_VERSION_NUMBER >= 0x030000
gnutls_datum_t uri;
int ret;
uschar sep = '\n';
gstring * list = NULL;

if (mod)
  if (*mod == '>' && *++mod) sep = *mod++;

for (int index = 0;; index++)
  {
  ret = gnutls_x509_crt_get_authority_info_access((gnutls_x509_crt_t)cert,
	  index, GNUTLS_IA_OCSP_URI, &uri, NULL);

  if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    return string_from_gstring(list);
  if (ret < 0)
    return g_err("gai", __FUNCTION__, ret);

  list = string_append_listele_n(list, sep, uri.data, uri.size);
  }
/*NOTREACHED*/

#else

expand_string_message =
  string_sprintf("%s: OCSP support with GnuTLS requires version 3.0.0\n",
    __FUNCTION__);
return NULL;

#endif
}

uschar *
tls_cert_crl_uri(void * cert, const uschar * mod)
{
int ret;
uschar sep = '\n';
gstring * list = NULL;

if (mod)
  if (*mod == '>' && *++mod) sep = *mod++;

for (int index = 0;; index++)
  {
  uschar * ele;
  size_t siz = 0;
  switch(ret = gnutls_x509_crt_get_crl_dist_points(
    (gnutls_x509_crt_t)cert, index, NULL, &siz, NULL, NULL))
    {
    case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
      return string_from_gstring(list);
    case GNUTLS_E_SHORT_MEMORY_BUFFER:
      break;
    default:
      return g_err("gc0", __FUNCTION__, ret);
    }

  ele = store_get(siz, GET_TAINTED);
  if ((ret = gnutls_x509_crt_get_crl_dist_points(
      (gnutls_x509_crt_t)cert, index, ele, &siz, NULL, NULL)) < 0)
    return g_err("gc1", __FUNCTION__, ret);

  list = string_append_listele_n(list, sep, ele, siz);
  }
/*NOTREACHED*/
}


/*****************************************************
*  Certificate operator routines
*****************************************************/
uschar *
tls_cert_der_b64(void * cert)
{
size_t len = 0;
uschar * cp = NULL;
int fail;

if (  (fail = gnutls_x509_crt_export((gnutls_x509_crt_t)cert,
	GNUTLS_X509_FMT_DER, cp, &len)) != GNUTLS_E_SHORT_MEMORY_BUFFER
   || !(cp = store_get((int)len, GET_TAINTED), TRUE)	/* tainted */
   || (fail = gnutls_x509_crt_export((gnutls_x509_crt_t)cert,
        GNUTLS_X509_FMT_DER, cp, &len))
   )
  {
  log_write(0, LOG_MAIN, "TLS error in certificate export: %s",
    gnutls_strerror(fail));
  return NULL;
  }
return b64encode(CUS cp, (int)len);
}


static uschar *
fingerprint(gnutls_x509_crt_t cert, gnutls_digest_algorithm_t algo)
{
int ret;
size_t siz = 0;
uschar * cp;
uschar * cp2;

if ((ret = gnutls_x509_crt_get_fingerprint(cert, algo, NULL, &siz))
    != GNUTLS_E_SHORT_MEMORY_BUFFER)
  return g_err("gf0", __FUNCTION__, ret);

cp = store_get(siz*3+1, GET_TAINTED);
if ((ret = gnutls_x509_crt_get_fingerprint(cert, algo, cp, &siz)) < 0)
  return g_err("gf1", __FUNCTION__, ret);

for (uschar * cp3 = cp2 = cp+siz; cp < cp2; cp++)
  cp3 += sprintf(CS cp3, "%02X", *cp);
return cp2;
}


uschar *
tls_cert_fprt_md5(void * cert)
{
return fingerprint((gnutls_x509_crt_t)cert, GNUTLS_DIG_MD5);
}

uschar *
tls_cert_fprt_sha1(void * cert)
{
return fingerprint((gnutls_x509_crt_t)cert, GNUTLS_DIG_SHA1);
}

uschar *
tls_cert_fprt_sha256(void * cert)
{
return fingerprint((gnutls_x509_crt_t)cert, GNUTLS_DIG_SHA256);
}


/* vi: aw ai sw=2
*/
/* End of tlscert-gnu.c */
