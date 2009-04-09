/**
 * \file rsa.h
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
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

/* $Cambridge: exim/src/src/pdkim/rsa.h,v 1.1.2.4 2009/04/09 07:49:11 tom Exp $ */

#ifndef POLARSSL_RSA_H
#define POLARSSL_RSA_H

#include "bignum.h"

#define POLARSSL_ERR_RSA_BAD_INPUT_DATA                    -0x0400
#define POLARSSL_ERR_RSA_INVALID_PADDING                   -0x0410
#define POLARSSL_ERR_RSA_KEY_GEN_FAILED                    -0x0420
#define POLARSSL_ERR_RSA_KEY_CHECK_FAILED                  -0x0430
#define POLARSSL_ERR_RSA_PUBLIC_FAILED                     -0x0440
#define POLARSSL_ERR_RSA_PRIVATE_FAILED                    -0x0450
#define POLARSSL_ERR_RSA_VERIFY_FAILED                     -0x0460
#define POLARSSL_ERR_RSA_OUTPUT_TO_LARGE                   -0x0470

#define POLARSSL_ERR_ASN1_OUT_OF_DATA                      -0x0014
#define POLARSSL_ERR_ASN1_UNEXPECTED_TAG                   -0x0016
#define POLARSSL_ERR_ASN1_INVALID_LENGTH                   -0x0018
#define POLARSSL_ERR_ASN1_LENGTH_MISMATCH                  -0x001A
#define POLARSSL_ERR_ASN1_INVALID_DATA                     -0x001C

#define POLARSSL_ERR_X509_FEATURE_UNAVAILABLE              -0x0020
#define POLARSSL_ERR_X509_CERT_INVALID_PEM                 -0x0040
#define POLARSSL_ERR_X509_CERT_INVALID_FORMAT              -0x0060
#define POLARSSL_ERR_X509_CERT_INVALID_VERSION             -0x0080
#define POLARSSL_ERR_X509_CERT_INVALID_SERIAL              -0x00A0
#define POLARSSL_ERR_X509_CERT_INVALID_ALG                 -0x00C0
#define POLARSSL_ERR_X509_CERT_INVALID_NAME                -0x00E0
#define POLARSSL_ERR_X509_CERT_INVALID_DATE                -0x0100
#define POLARSSL_ERR_X509_CERT_INVALID_PUBKEY              -0x0120
#define POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE           -0x0140
#define POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS          -0x0160
#define POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION             -0x0180
#define POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG             -0x01A0
#define POLARSSL_ERR_X509_CERT_UNKNOWN_PK_ALG              -0x01C0
#define POLARSSL_ERR_X509_CERT_SIG_MISMATCH                -0x01E0
#define POLARSSL_ERR_X509_CERT_VERIFY_FAILED               -0x0200
#define POLARSSL_ERR_X509_KEY_INVALID_PEM                  -0x0220
#define POLARSSL_ERR_X509_KEY_INVALID_VERSION              -0x0240
#define POLARSSL_ERR_X509_KEY_INVALID_FORMAT               -0x0260
#define POLARSSL_ERR_X509_KEY_INVALID_ENC_IV               -0x0280
#define POLARSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG              -0x02A0
#define POLARSSL_ERR_X509_KEY_PASSWORD_REQUIRED            -0x02C0
#define POLARSSL_ERR_X509_KEY_PASSWORD_MISMATCH            -0x02E0
#define POLARSSL_ERR_X509_POINT_ERROR                      -0x0300
#define POLARSSL_ERR_X509_VALUE_TO_LENGTH                  -0x0320

/*
 * DER constants
 */
#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80

/*
 * PKCS#1 constants
 */
#define RSA_RAW         0
#define RSA_MD2         2
#define RSA_MD4         3
#define RSA_MD5         4
#define RSA_SHA1        5
#define RSA_SHA256      6

#define RSA_PUBLIC      0
#define RSA_PRIVATE     1

#define RSA_PKCS_V15    0
#define RSA_PKCS_V21    1

#define RSA_SIGN        1
#define RSA_CRYPT       2

/*
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * Digest ::= OCTET STRING
 */
#define ASN1_HASH_MDX                       \
    "\x30\x20\x30\x0C\x06\x08\x2A\x86\x48"  \
    "\x86\xF7\x0D\x02\x00\x05\x00\x04\x10"

#define ASN1_HASH_SHA1                      \
    "\x30\x21\x30\x09\x06\x05\x2B\x0E\x03"  \
    "\x02\x1A\x05\x00\x04\x14"

#define ASN1_HASH_SHA256                    \
    "\x30\x31\x30\x0d\x06\x09\x60\x86\x48"  \
    "\x01\x65\x03\x04\x02\x01\x05\x00\x04"  \
    "\x20"

/**
 * \brief          RSA context structure
 */
typedef struct
{
    int ver;                    /*!<  always 0          */
    int len;                    /*!<  size(N) in chars  */

    mpi N;                      /*!<  public modulus    */
    mpi E;                      /*!<  public exponent   */

    mpi D;                      /*!<  private exponent  */
    mpi P;                      /*!<  1st prime factor  */
    mpi Q;                      /*!<  2nd prime factor  */
    mpi DP;                     /*!<  D % (P - 1)       */
    mpi DQ;                     /*!<  D % (Q - 1)       */
    mpi QP;                     /*!<  1 / (Q % P)       */

    mpi RN;                     /*!<  cached R^2 mod N  */
    mpi RP;                     /*!<  cached R^2 mod P  */
    mpi RQ;                     /*!<  cached R^2 mod Q  */

    int padding;                /*!<  1.5 or OAEP/PSS   */
    int hash_id;                /*!<  hash identifier   */
    int (*f_rng)(void *);       /*!<  RNG function      */
    void *p_rng;                /*!<  RNG parameter     */
}
rsa_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize an RSA context
 *
 * \param ctx      RSA context to be initialized
 * \param padding  RSA_PKCS_V15 or RSA_PKCS_V21
 * \param hash_id  RSA_PKCS_V21 hash identifier
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using RSA_PKCS_V15 padding.
 *
 * \note           Currently (xyssl-0.8), RSA_PKCS_V21 padding
 *                 is not supported.
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id,
               int (*f_rng)(void *),
               void *p_rng );

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context that will hold the key
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 *
 * \note           rsa_init() must be called beforehand to setup
 *                 the RSA context (especially f_rng and p_rng).
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_gen_key( rsa_context *ctx, int nbits, int exponent );

/**
 * \brief          Check a public RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_check_pubkey( rsa_context *ctx );

/**
 * \brief          Check a private RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_check_privkey( rsa_context *ctx );

/**
 * \brief          Do an RSA public key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           This function does NOT take care of message
 *                 padding. Also, be sure to set input[0] = 0.
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_public( rsa_context *ctx,
                unsigned char *input,
                unsigned char *output );

/**
 * \brief          Do an RSA private key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_private( rsa_context *ctx,
                 unsigned char *input,
                 unsigned char *output );

/**
 * \brief          Add the message padding, then do an RSA operation
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param ilen     contains the the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int mode, int  ilen,
                       unsigned char *input,
                       unsigned char *output );

/**
 * \brief          Do an RSA operation, then remove the message padding
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param olen     will contain the plaintext length
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       unsigned char *input,
                       unsigned char *output,
               int output_max_len);

/**
 * \brief          Do a private RSA to sign a message digest
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param hash_id  RSA_RAW, RSA_MD{2,4,5} or RSA_SHA{1,256}
 * \param hashlen  message digest length (for RSA_RAW only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    unsigned char *hash,
                    unsigned char *sig );

/**
 * \brief          Do a public RSA and check the message digest
 *
 * \param ctx      points to an RSA public key
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param hash_id  RSA_RAW, RSA_MD{2,4,5} or RSA_SHA{1,256}
 * \param hashlen  message digest length (for RSA_RAW only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      unsigned char *hash,
                      unsigned char *sig );

/**
 * \brief          Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx );

int rsa_parse_public_key( rsa_context *rsa, unsigned char *buf, int buflen );

int rsa_parse_key( rsa_context *rsa, unsigned char *buf, int buflen,
                                     unsigned char *pwd, int pwdlen );

#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
