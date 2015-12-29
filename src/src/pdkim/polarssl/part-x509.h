/* *************** begin copy from x509.h  ************************/
/**
 * \file x509.h
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

#ifndef POLARSSL_PART_X509_H
#define POLARSSL_PART_X509_H

/*
 * ASN1 Error codes
 *
 * These error codes will be OR'ed to X509 error codes for
 * higher error granularity.
 */
#define POLARSSL_ERR_ASN1_OUT_OF_DATA                      0x0014
#define POLARSSL_ERR_ASN1_UNEXPECTED_TAG                   0x0016
#define POLARSSL_ERR_ASN1_INVALID_LENGTH                   0x0018
#define POLARSSL_ERR_ASN1_LENGTH_MISMATCH                  0x001A
#define POLARSSL_ERR_ASN1_INVALID_DATA                     0x001C

/*
 * X509 Error codes
 */
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
#define ASN1_GENERALIZED_TIME        0x18
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80
/* ***************   end copy from x509.h  ************************/

#endif /* part-x509.h */
