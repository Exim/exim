/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2014 */

/* This module provides TLS (aka SSL) support for Exim using the OpenSSL
library. It is #included into the tls.c file when that library is used.
*/


/* Heading stuff */

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


/*****************************************************
*  Export/import a certificate, binary/printable
*****************************************************/
int
tls_export_cert(uschar * buf, size_t buflen, void * cert)
{
BIO * bp = BIO_new(BIO_s_mem());
int fail;

if ((fail = PEM_write_bio_X509(bp, (X509 *)cert) ? 0 : 1))
  log_write(0, LOG_MAIN, "TLS error in certificate export: %s",
    ERR_error_string(ERR_get_error(), NULL));
else
  {
  char * cp = CS buf;
  int n;
  buflen -= 2;
  for(;;)
    {
    if ((n = BIO_gets(bp, cp, (int)buflen)) <= 0) break;
    cp += n+1;
    buflen -= n+1;
    cp[-2] = '\\'; cp[-1] = 'n'; /* newline->"\n" */
    }				 /* compat with string_printing() */
  *cp = '\0';
  }

BIO_free(bp);
return fail;
}

int
tls_import_cert(const uschar * buf, void ** cert)
{
void * reset_point = store_get(0);
const uschar * cp = string_unprinting(US buf);
BIO * bp;
X509 * x;

bp = BIO_new_mem_buf(US cp, -1);
x = PEM_read_bio_X509(bp, NULL, 0, NULL);
int fail = 0;
if (!x)
  fail = 1;
else
  *cert = (void *)x;
BIO_free(bp);
store_reset(reset_point);
return fail;
}

void
tls_free_cert(void * cert)
{
X509_free((X509 *)cert);
}

/*****************************************************
*  Certificate field extraction routines
*****************************************************/
static uschar *
bio_string_copy(BIO * bp, int len)
{
uschar * cp = "";
len = len > 0 ? (int) BIO_get_mem_data(bp, &cp) : 0;
cp = string_copyn(cp, len);
BIO_free(bp);
return cp;
}

static uschar *
asn1_time_copy(const ASN1_TIME * time)
{
BIO * bp = BIO_new(BIO_s_mem());
int len = ASN1_TIME_print(bp, time);
return bio_string_copy(bp, len);
}

static uschar *
x509_name_copy(X509_NAME * name)
{
BIO * bp = BIO_new(BIO_s_mem());
int len_good =
  X509_NAME_print_ex(bp, name, 0, XN_FLAG_RFC2253) >= 0
  ? 1 : 0;
return bio_string_copy(bp, len_good);
}

/**/

uschar *
tls_cert_issuer(void * cert)
{
return x509_name_copy(X509_get_issuer_name((X509 *)cert));
}

uschar *
tls_cert_not_before(void * cert)
{
return asn1_time_copy(X509_get_notBefore((X509 *)cert));
}

uschar *
tls_cert_not_after(void * cert)
{
return asn1_time_copy(X509_get_notAfter((X509 *)cert));
}

uschar *
tls_cert_serial_number(void * cert)
{
uschar txt[256];
BIO * bp = BIO_new(BIO_s_mem());
int len = i2a_ASN1_INTEGER(bp, X509_get_serialNumber((X509 *)cert));

if (len < sizeof(txt))
  BIO_read(bp, txt, len);
else
  len = 0;
BIO_free(bp);
return string_copynlc(txt, len);	/* lowercase */
}

uschar *
tls_cert_signature(void * cert)
{
BIO * bp = BIO_new(BIO_s_mem());
uschar * cp = NULL;

if (X509_print_ex(bp, (X509 *)cert, 0,
  X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION | X509_FLAG_NO_SERIAL | 
  X509_FLAG_NO_SIGNAME | X509_FLAG_NO_ISSUER | X509_FLAG_NO_VALIDITY | 
  X509_FLAG_NO_SUBJECT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_EXTENSIONS | 
  /* X509_FLAG_NO_SIGDUMP is the missing one */
  X509_FLAG_NO_AUX) == 1)
  {
  long len = BIO_get_mem_data(bp, &cp);
  cp = string_copyn(cp, len);
  }
BIO_free(bp);
return cp;
}

uschar *
tls_cert_signature_algorithm(void * cert)
{
return string_copy(OBJ_nid2ln(X509_get_signature_type((X509 *)cert)));
}

uschar *
tls_cert_subject(void * cert)
{
return x509_name_copy(X509_get_subject_name((X509 *)cert));
}

uschar *
tls_cert_version(void * cert)
{
return string_sprintf("%d", X509_get_version((X509 *)cert));
}

uschar *
tls_cert_ext_by_oid(void * cert, uschar * oid, int idx)
{
int nid = OBJ_create(oid, "", "");
int nidx = X509_get_ext_by_NID((X509 *)cert, nid, idx);
X509_EXTENSION * ex = X509_get_ext((X509 *)cert, nidx);
ASN1_OCTET_STRING * adata = X509_EXTENSION_get_data(ex);
BIO * bp = BIO_new(BIO_s_mem());
long len;
uschar * cp1;
uschar * cp2;
uschar * cp3;

M_ASN1_OCTET_STRING_print(bp, adata);
/* binary data, DER encoded */

/* just dump for now */
len = BIO_get_mem_data(bp, &cp1);
cp3 = cp2 = store_get(len*3+1);

while(len)
  {
  sprintf(cp2, "%.2x ", *cp1++);
  cp2 += 3;
  len--;
  }
cp2[-1] = '\0';

return cp3;
}

uschar *
tls_cert_subject_altname(void * cert)
{
uschar * cp;
STACK_OF(GENERAL_NAME) * san = (STACK_OF(GENERAL_NAME) *)
  X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, NULL, NULL);

if (!san) return NULL;

while (sk_GENERAL_NAME_num(san) > 0)
  {
  GENERAL_NAME * namePart = sk_GENERAL_NAME_pop(san);
  switch (namePart->type)
    {
    case GEN_URI:
      cp = string_sprintf("URI=%s",
	    ASN1_STRING_data(namePart->d.uniformResourceIdentifier));
      return cp;
    case GEN_EMAIL:
      cp = string_sprintf("email=%s",
	    ASN1_STRING_data(namePart->d.rfc822Name));
      return cp;
    default:
      cp = string_sprintf("Unrecognisable");
      return cp;
    }
  }

/* sk_GENERAL_NAME_pop_free(gen_names, GENERAL_NAME_free);  ??? */
return cp;
}

uschar *
tls_cert_ocsp_uri(void * cert)
{
STACK_OF(ACCESS_DESCRIPTION) * ads = (STACK_OF(ACCESS_DESCRIPTION) *)
  X509_get_ext_d2i((X509 *)cert, NID_info_access, NULL, NULL);
int adsnum = sk_ACCESS_DESCRIPTION_num(ads);
int i;

for (i = 0; i < adsnum; i++)
  {
  ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value(ads, i);

  if (ad && OBJ_obj2nid(ad->method) == NID_ad_OCSP)
    return string_copy( ASN1_STRING_data(ad->location->d.ia5) );
  }

return NULL;
}

uschar *
tls_cert_crl_uri(void * cert)
{
STACK_OF(DIST_POINT) * dps = (STACK_OF(DIST_POINT) *)
  X509_get_ext_d2i((X509 *)cert,  NID_crl_distribution_points,
    NULL, NULL);
DIST_POINT * dp;
int dpsnum = sk_DIST_POINT_num(dps);
int i;

if (dps) for (i = 0; i < dpsnum; i++)
  if ((dp = sk_DIST_POINT_value(dps, i)))
    {
    STACK_OF(GENERAL_NAME) * names = dp->distpoint->name.fullname;
    GENERAL_NAME * np;
    int nnum = sk_GENERAL_NAME_num(names);
    int j;

    for (j = 0; j < nnum; j++)
      if (  (np = sk_GENERAL_NAME_value(names, j))
	 && np->type == GEN_URI
	 )
	return string_copy(ASN1_STRING_data(
	  np->d.uniformResourceIdentifier));
    }
return NULL;
}

/* vi: aw ai sw=2
*/
/* End of tlscert-openssl.c */
