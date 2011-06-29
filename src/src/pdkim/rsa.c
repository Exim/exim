/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "rsa.h"
#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* *************** begin copy from x509parse.c ********************/
/*
 * ASN.1 DER decoding routines
 */
static int asn1_get_len( unsigned char **p,
                         const unsigned char *end,
                         int *len )
{
    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( ( **p & 0x80 ) == 0 )
        *len = *(*p)++;
    else
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( ( end - *p ) < 2 )
                return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if( ( end - *p ) < 3 )
                return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

            *len = ( (*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        default:
            return( POLARSSL_ERR_ASN1_INVALID_LENGTH );
            break;
        }
    }

    if( *len > (int) ( end - *p ) )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    return( 0 );
}

static int asn1_get_tag( unsigned char **p,
                         const unsigned char *end,
                         int *len, int tag )
{
    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != tag )
        return( POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;

    return( asn1_get_len( p, end, len ) );
}

static int asn1_get_int( unsigned char **p,
                         const unsigned char *end,
                         int *val )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    if( len > (int) sizeof( int ) || ( **p & 0x80 ) != 0 )
        return( POLARSSL_ERR_ASN1_INVALID_LENGTH );

    *val = 0;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return( 0 );
}

static int asn1_get_mpi( unsigned char **p,
                         const unsigned char *end,
                         mpi *X )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    ret = mpi_read_binary( X, *p, len );

    *p += len;

    return( ret );
}
/* ***************   end copy from x509parse.c ********************/




/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(POLARSSL_GENPRIME)

/*
 * Generate an RSA keypair
 */
int rsa_gen_key( rsa_context *ctx,
        int (*f_rng)(void *),
        void *p_rng,
        int nbits, int exponent )
{
    int ret;
    mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1, &Q1, &H, &G, NULL );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0, 
                                f_rng, p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &G, &H, &Q1, &P1, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}

#endif

/*
 * Check a public RSA key
 */
int rsa_check_pubkey( const rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 ||
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > 4096 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( const rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    mpi_init( &PQ, &DE, &P1, &Q1, &H, &I, &G, &G2, &L1, &L2, NULL );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );  
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) == 0 &&
        mpi_cmp_int( &L2, 0 ) == 0 &&
        mpi_cmp_int( &I, 1 ) == 0 &&
        mpi_cmp_int( &G, 1 ) == 0 )
    {
        mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
        return( 0 );
    }

    
cleanup:

    mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
    return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED | ret );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret, olen;
    mpi T;

    mpi_init( &T, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context *ctx,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret, olen;
    mpi T, T1, T2;

    mpi_init( &T, &T1, &T2, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

#if 0
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *),
                       void *p_rng,
                       int mode, int  ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    int nb_pad, olen;
    unsigned char *p = output;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( ilen < 0 || olen < ilen + 11 || f_rng == NULL )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            nb_pad = olen - 3 - ilen;

            *p++ = 0;
            *p++ = RSA_CRYPT;

            while( nb_pad-- > 0 )
            {
                int rng_dl = 100;

                do {
                    *p = (unsigned char) f_rng( p_rng );
                } while( *p == 0 && --rng_dl );

                // Check if RNG failed to generate data
                //
                if( rng_dl == 0 )
                    return POLARSSL_ERR_RSA_RNG_FAILED;

                p++;
            }
            *p++ = 0;
            memcpy( p, input, ilen );
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       int output_max_len)
{
    int ret, ilen;
    unsigned char *p;
    unsigned char buf[1024];

    ilen = ctx->len;

    if( ilen < 16 || ilen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_CRYPT )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + ilen - 1 )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    if (ilen - (int)(p - buf) > output_max_len)
      return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (int)(p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    int nb_pad, olen;
    unsigned char *p = sig;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            switch( hash_id )
            {
                case SIG_RSA_RAW:
                    nb_pad = olen - 3 - hashlen;
                    break;

                case SIG_RSA_MD2:
                case SIG_RSA_MD4:
                case SIG_RSA_MD5:
                    nb_pad = olen - 3 - 34;
                    break;

                case SIG_RSA_SHA1:
                    nb_pad = olen - 3 - 35;
                    break;

                case SIG_RSA_SHA224:
                    nb_pad = olen - 3 - 47;
                    break;

                case SIG_RSA_SHA256:
                    nb_pad = olen - 3 - 51;
                    break;

                case SIG_RSA_SHA384:
                    nb_pad = olen - 3 - 67;
                    break;

                case SIG_RSA_SHA512:
                    nb_pad = olen - 3 - 83;
                    break;


                default:
                    return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            if( nb_pad < 8 )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            *p++ = 0;
            *p++ = RSA_SIGN;
            memset( p, 0xFF, nb_pad );
            p += nb_pad;
            *p++ = 0;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case SIG_RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case SIG_RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case SIG_RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case SIG_RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        case SIG_RSA_SHA224:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 28 );
            p[1] += 28; p[14] = 4; p[18] += 28; break;

        case SIG_RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

        case SIG_RSA_SHA384:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 48 );
            p[1] += 48; p[14] = 2; p[18] += 48; break;

        case SIG_RSA_SHA512:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 64 );
            p[1] += 64; p[14] = 3; p[18] += 64; break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      const unsigned char *hash,
                      unsigned char *sig )
{
    int ret, len, siglen;
    unsigned char *p, c;
    unsigned char buf[1024];

    siglen = ctx->len;

    if( siglen < 16 || siglen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_SIGN )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + siglen - 1 || *p != 0xFF )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    len = siglen - (int)( p - buf );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && hash_id == SIG_RSA_MD2 ) ||
            ( c == 4 && hash_id == SIG_RSA_MD4 ) ||
            ( c == 5 && hash_id == SIG_RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 )
                return( 0 );
            else
                return( POLARSSL_ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && hash_id == SIG_RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
            memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }
    if( ( len == 19 + 28 && p[14] == 4 && hash_id == SIG_RSA_SHA224 ) ||
        ( len == 19 + 32 && p[14] == 1 && hash_id == SIG_RSA_SHA256 ) ||
        ( len == 19 + 48 && p[14] == 2 && hash_id == SIG_RSA_SHA384 ) ||
        ( len == 19 + 64 && p[14] == 3 && hash_id == SIG_RSA_SHA512 ) )
    {
        c = p[1] - 17;
        p[1] = 17;
        p[14] = 0;

        if( p[18] == c &&
                memcmp( p, ASN1_HASH_SHA2X, 18 ) == 0 &&
                memcmp( p + 19, hash, c ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    if( len == hashlen && hash_id == SIG_RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    return( POLARSSL_ERR_RSA_INVALID_PADDING );
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->RQ, &ctx->RP, &ctx->RN,
              &ctx->QP, &ctx->DQ, &ctx->DP,
              &ctx->Q,  &ctx->P,  &ctx->D,
              &ctx->E,  &ctx->N,  NULL );
}


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
        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
            return( ret | POLARSSL_ERR_X509_KEY_INVALID_PEM );

        if( ( buf = (unsigned char *) malloc( len ) ) == NULL )
            return( 1 );

        if( ( ret = base64_decode( buf, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( buf );
            return( ret | POLARSSL_ERR_X509_KEY_INVALID_PEM );
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
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    end = p + len;

    if( ( ret = asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    if( rsa->ver != 0 )
    {
        if( s1 != NULL )
            free( buf );

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
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret | POLARSSL_ERR_X509_KEY_INVALID_FORMAT );
    }

    rsa->len = mpi_size( &rsa->N );

    if( p != end )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = rsa_check_privkey( rsa ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret );
    }

    if( s1 != NULL )
        free( buf );

    return( 0 );
}
