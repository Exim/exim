
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Unix includes */

typedef unsigned char uschar;

#define CS   (char *)
#define US   (unsigned char *)

#define FALSE         0
#define TRUE          1



#ifdef HAVE_GNUTLS


#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#if GNUTLS_VERSION_NUMBER >= 0x030600
# define SIGN_HAVE_ED25519
#endif



static uschar *enc64table =
  US"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uschar *
b64encode(uschar *clear, int len)
{
uschar *code = malloc(4*((len+2)/3) + 2);
uschar *p = code;

while (len-- >0)
  {
  int x, y;

  x = *clear++;
  *p++ = enc64table[(x >> 2) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(x << 4) & 63];
    *p++ = '=';
    *p++ = '=';
    break;
    }

  y = *clear++;
  *p++ = enc64table[((x << 4) | ((y >> 4) & 15)) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(y << 2) & 63];
    *p++ = '=';
    break;
    }

  x = *clear++;
  *p++ = enc64table[((y << 2) | ((x >> 6) & 3)) & 63];

  *p++ = enc64table[x & 63];
  }

*p = 0;

return code;
}

/*************************************************
*                 Main Program                   *
*************************************************/


int
main(int argc, char **argv)
{
uschar * pemfile = argv[1];
int fd;
uschar buf[1024];
int len, rc;
gnutls_privkey_t privkey;
gnutls_datum_t k;
gnutls_pubkey_t pubkey;
uschar * b64;

#ifdef SIGN_HAVE_ED25519
if ((fd = open(CS pemfile, O_RDONLY)) < 0)
  exit(1);

if ((len = read(fd, buf, sizeof(buf)-1)) < 0)
  exit(2);

k.data = buf;
k.size = len;

if (  (rc = gnutls_privkey_init(&privkey))
   || (rc = gnutls_privkey_import_x509_raw(privkey, &k, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS_PLAIN))
   || (rc = gnutls_pubkey_init(&pubkey))
   || (rc = gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE, 0))
   || (rc = gnutls_pubkey_export_ecc_raw2(pubkey, NULL, &k, NULL, GNUTLS_EXPORT_FLAG_NO_LZ))
   )
  fprintf(stderr, "%s\n", gnutls_strerror(rc));

b64 = b64encode(k.data, k.size);

printf("%s\n", b64);
exit(0);

#else
fprintf(stderr, "No support for ed25519 signing in GnuTLS (version %s)\n", gnutls_check_version(NULL));
exit(3);
#endif
}

#endif

#ifdef HAVE_OPENSSL
int
main(int argc, char **argv)
{
fprintf(stderr, "No support for ed25519 signing in OpenSSL\n");
exit(3);
}

#endif
