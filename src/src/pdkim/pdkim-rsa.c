#include "pdkim-rsa.h"
#include <stdlib.h>
#include <string.h>
#include "polarssl/private-x509parse_c.h"

/* PDKIM code (not copied from polarssl) */
/*
 * Parse a public RSA key

OpenSSL RSA public key ASN1 container
  0:d=0  hl=3 l= 159 cons: SEQUENCE
  3:d=1  hl=2 l=  13 cons: SEQUENCE
  5:d=2  hl=2 l=   9 prim: OBJECT:rsaEncryption
 16:d=2  hl=2 l=   0 prim: NULL
 18:d=1  hl=3 l= 141 prim: BIT STRING:RSAPublicKey (below)

RSAPublicKey ASN1 container
  0:d=0  hl=3 l= 137 cons: SEQUENCE
  3:d=1  hl=3 l= 129 prim: INTEGER:Public modulus
135:d=1  hl=2 l=   3 prim: INTEGER:Public exponent
*/

int rsa_parse_public_key( rsa_context *rsa, unsigned char *buf, int buflen )
{
    unsigned char *p, *end;
    int ret, len;

    p = buf;
    end = buf+buflen;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 ) {
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) == 0 ) {
        /* Skip over embedded rsaEncryption Object */
        p+=len;

        /* The RSAPublicKey ASN1 container is wrapped in a BIT STRING */
        if( ( ret = asn1_get_tag( &p, end, &len,
                ASN1_BIT_STRING ) ) != 0 ) {
            return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
        }

        /* Limit range to that BIT STRING */
        end = p + len;
        p++;

        if( ( ret = asn1_get_tag( &p, end, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 ) {
            return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
        }
    }

    if ( ( ( ret = asn1_get_mpi( &p, end, &(rsa->N)  ) ) == 0 ) &&
         ( ( ret = asn1_get_mpi( &p, end, &(rsa->E)  ) ) == 0 ) ) {
        rsa->len = mpi_size( &rsa->N );
        return 0;
    }

    return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
}

/*
 * Parse a private RSA key
 */
int rsa_parse_key( rsa_context *rsa, unsigned char *buf, int buflen,
                                     unsigned char *pwd, int pwdlen )
{
    int ret, len, enc;
    unsigned char *s1, *s2;
    unsigned char *p, *end;

    s1 = (unsigned char *) strstr( (char *) buf,
        "-----BEGIN RSA PRIVATE KEY-----" );

    if( s1 != NULL )
    {
        s2 = (unsigned char *) strstr( (char *) buf,
            "-----END RSA PRIVATE KEY-----" );

        if( s2 == NULL || s2 <= s1 )
            return( POLARSSL_ERR_X509_KEY_INVALID_PEM );

        s1 += 31;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( POLARSSL_ERR_X509_KEY_INVALID_PEM );

        enc = 0;

        if( memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
        {
            return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
        }

        len = 0;
	{
	extern unsigned char * string_copyn(const unsigned char *, int);
	extern int b64decode(unsigned char *, unsigned char **);
#define POLARSSL_ERR_BASE64_INVALID_CHARACTER              0x0012

	s1 = string_copyn(s1, s2-s1); /* need nul-terminated string */
	if ((len = b64decode(s1, &buf)) < 0)
            return POLARSSL_ERR_BASE64_INVALID_CHARACTER
		| POLARSSL_ERR_X509_KEY_INVALID_PEM;
	}

        buflen = len;

        if( enc != 0 )
        {
            return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
        }
    }

    memset( rsa, 0, sizeof( rsa_context ) );

    p = buf;
    end = buf + buflen;

    /*
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    end = p + len;

    if( ( ret = asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    if( rsa->ver != 0 )
    {
        rsa_free( rsa );
        return( ret | POLARSSL_ERR_X509_KEY_INVALID_VERSION );
    }

    if( ( ret = asn1_get_mpi( &p, end, &rsa->N  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->E  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->D  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->P  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->Q  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DP ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DQ ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->QP ) ) != 0 )
    {
        rsa_free( rsa );
        return( ret | POLARSSL_ERR_X509_KEY_INVALID_FORMAT );
    }

    rsa->len = mpi_size( &rsa->N );

    if( p != end )
    {
        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = rsa_check_privkey( rsa ) ) != 0 )
    {
        rsa_free( rsa );
        return( ret );
    }

    return( 0 );
}
