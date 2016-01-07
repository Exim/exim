#include "crypt_ver.h"

#ifdef SHA_POLARSSL	/* remainder of file */

#include "polarssl/bignum.h"
#include "polarssl/part-x509.h"
#include "polarssl/private-x509parse_c.h"

/* all calls are from src/pdkim/pdkim-rsa.c */

/* *************** begin copy from x509parse.c ********************/
/*
 *  X.509 certificate and private key decoding
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
 *  The ITU-T X.509 standard defines a certificat format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc2459.txt
 *  http://www.ietf.org/rfc/rfc3279.txt
 *
 *  ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */


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

/* This function is not exported by PolarSSL 0.14.2
 * static */
int asn1_get_tag( unsigned char **p,
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

/* This function is not exported by PolarSSL 0.14.2
 * static */
int asn1_get_int( unsigned char **p,
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

/* This function is not exported by PolarSSL 0.14.2
 * static */
int asn1_get_mpi( unsigned char **p,
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
#endif
