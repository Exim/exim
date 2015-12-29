#include "polarssl/part-x509.h"
#include "polarssl/rsa.h"

/* PDKIM declarations (not part of polarssl) */
int rsa_parse_public_key( rsa_context *rsa, unsigned char *buf, int buflen );
int rsa_parse_key( rsa_context *rsa, unsigned char *buf, int buflen,
                                     unsigned char *pwd, int pwdlen );

