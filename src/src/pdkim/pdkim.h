/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2009 - 2012  Tom Kistner <tom@duncanthrax.net>
 *
 *  http://duncanthrax.net/pdkim/
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

/* -------------------------------------------------------------------------- */
/* Debugging. This can also be enabled/disabled at run-time. I recommend to
   leave it defined. */
#define PDKIM_DEBUG

/* -------------------------------------------------------------------------- */
/* Length of the preallocated buffer for the "answer" from the dns/txt
   callback function. This should match the maximum RDLENGTH from DNS. */
#define PDKIM_DNS_TXT_MAX_RECLEN    (1 << 16)

/* -------------------------------------------------------------------------- */
/* Function success / error codes */
#define PDKIM_OK                      0
#define PDKIM_FAIL                   -1
#define PDKIM_ERR_OOM              -100
#define PDKIM_ERR_RSA_PRIVKEY      -101
#define PDKIM_ERR_RSA_SIGNING      -102
#define PDKIM_ERR_LONG_LINE        -103
#define PDKIM_ERR_BUFFER_TOO_SMALL -104

/* -------------------------------------------------------------------------- */
/* Main/Extended verification status */
#define PDKIM_VERIFY_NONE      0
#define PDKIM_VERIFY_INVALID   1
#define PDKIM_VERIFY_FAIL      2
#define PDKIM_VERIFY_PASS      3

#define PDKIM_VERIFY_FAIL_BODY                  1
#define PDKIM_VERIFY_FAIL_MESSAGE               2
#define PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE 3
#define PDKIM_VERIFY_INVALID_BUFFER_SIZE        4
#define PDKIM_VERIFY_INVALID_PUBKEY_PARSING     5

/* -------------------------------------------------------------------------- */
/* Some parameter values */
#define PDKIM_QUERYMETHOD_DNS_TXT 0

#define PDKIM_ALGO_RSA_SHA256     0
#define PDKIM_ALGO_RSA_SHA1       1

#define PDKIM_CANON_SIMPLE        0
#define PDKIM_CANON_RELAXED       1

#define PDKIM_HASH_SHA256         0
#define PDKIM_HASH_SHA1           1

#define PDKIM_KEYTYPE_RSA         0

/* -------------------------------------------------------------------------- */
/* Some required forward declarations, please ignore */
typedef struct pdkim_stringlist pdkim_stringlist;
typedef struct pdkim_str pdkim_str;
typedef struct sha1_context sha1_context;
typedef struct sha2_context sha2_context;
#define HAVE_SHA1_CONTEXT
#define HAVE_SHA2_CONTEXT

/* -------------------------------------------------------------------------- */
/* Some concessions towards Redmond */
#ifdef WINDOWS
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif


/* -------------------------------------------------------------------------- */
/* Public key as (usually) fetched from DNS */
typedef struct pdkim_pubkey {
  char *version;                  /* v=  */
  char *granularity;              /* g=  */

  char *hashes;                   /* h=  */
  char *keytype;                  /* k=  */
  char *srvtype;                  /* s=  */
  char *notes;                    /* n=  */

  char *key;                      /* p=  */
  int   key_len;

  int   testing;                  /* t=y */
  int   no_subdomaining;          /* t=s */
} pdkim_pubkey;

/* -------------------------------------------------------------------------- */
/* Signature as it appears in a DKIM-Signature header */
typedef struct pdkim_signature {

  /* Bits stored in a DKIM signature header --------------------------- */

  /* (v=) The version, as an integer. Currently, always "1" */
  int version;

  /* (a=) The signature algorithm. Either PDKIM_ALGO_RSA_SHA256
     or PDKIM_ALGO_RSA_SHA1 */
  int algo;

  /* (c=x/) Header canonicalization method. Either PDKIM_CANON_SIMPLE
     or PDKIM_CANON_RELAXED */
  int canon_headers;

  /* (c=/x) Body canonicalization method. Either PDKIM_CANON_SIMPLE
     or PDKIM_CANON_RELAXED */
  int canon_body;

  /* (q=) Query Method. Currently, only PDKIM_QUERYMETHOD_DNS_TXT
     is specified */
  int querymethod;

  /* (s=) The selector string as given in the signature */
  char *selector;

  /* (d=) The domain as given in the signature */
  char *domain;

  /* (i=) The identity as given in the signature */
  char *identity;

  /* (t=) Timestamp of signature creation */
  unsigned long created;

  /* (x=) Timestamp of expiry of signature */
  unsigned long expires;

  /* (l=) Amount of hashed body bytes (after canonicalization). Default
     is -1. Note: a value of 0 means that the body is unsigned! */
  long bodylength;

  /* (h=) Colon-separated list of header names that are included in the
     signature */
  char *headernames;

  /* (z=) */
  char *copiedheaders;

  /* (b=) Raw signature data, along with its length in bytes */
  char *sigdata;
  int   sigdata_len;

  /* (bh=) Raw body hash data, along with its length in bytes */
  char *bodyhash;
  int   bodyhash_len;

  /* Folded DKIM-Signature: header. Singing only, NULL for verifying.
     Ready for insertion into the message. Note: Folded using CRLFTB,
     but final line terminator is NOT included. Note2: This buffer is
     free()d when you call pdkim_free_ctx(). */
  char *signature_header;

  /* The main verification status. Verification only. One of:

     PDKIM_VERIFY_NONE      Verification was not attempted. This status
                            should not appear.

     PDKIM_VERIFY_INVALID   There was an error while trying to verify
                            the signature. A more precise description
                            is available in verify_ext_status.

     PDKIM_VERIFY_FAIL      Verification failed because either the body
                            hash did not match, or the signature verification
                            failed. This means the message was modified.
                            Check verify_ext_status for the exact reason.

     PDKIM_VERIFY_PASS      Verification succeeded.
  */
  int verify_status;

  /* Extended verification status. Verification only. Depending on the value
     of verify_status, it can contain:

     For verify_status == PDKIM_VERIFY_INVALID:

        PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE
          Unable to retrieve a public key container.

        PDKIM_VERIFY_INVALID_BUFFER_SIZE
          Either the DNS name constructed to retrieve the public key record
          does not fit into PDKIM_DNS_TXT_MAX_NAMELEN bytes, or the retrieved
          record is longer than PDKIM_DNS_TXT_MAX_RECLEN bytes.

        PDKIM_VERIFY_INVALID_PUBKEY_PARSING
          (Syntax) error while parsing the retrieved public key record.


     For verify_status == PDKIM_VERIFY_FAIL:

        PDKIM_VERIFY_FAIL_BODY
          The calculated body hash does not match the advertised body hash
          from the bh= tag of the signature.

        PDKIM_VERIFY_FAIL_MESSAGE
          RSA verification of the signature (b= tag) failed.
  */
  int verify_ext_status;

  /* Pointer to a public key record that was used to verify the signature.
     See pdkim_pubkey declaration above for more information.
     Caution: is NULL if signing or if no record was retrieved. */
  pdkim_pubkey *pubkey;

  /* Pointer to the next pdkim_signature signature. NULL if signing or if
     this is the last signature. */
  void *next;

  /* Properties below this point are used internally only ------------- */

  /* Per-signature helper variables ----------------------------------- */
  sha1_context *sha1_body; /* SHA1 block                                */
  sha2_context *sha2_body; /* SHA256 block                              */
  unsigned long signed_body_bytes; /* How many body bytes we hashed     */
  pdkim_stringlist *headers; /* Raw headers included in the sig         */
  /* Signing specific ------------------------------------------------- */
  char *rsa_privkey;     /* Private RSA key                             */
  char *sign_headers;    /* To-be-signed header names                   */
  char *rawsig_no_b_val; /* Original signature header w/o b= tag value. */
} pdkim_signature;


/* -------------------------------------------------------------------------- */
/* Context to keep state between all operations. */
#define PDKIM_MODE_SIGN     0
#define PDKIM_MODE_VERIFY   1
#define PDKIM_INPUT_NORMAL  0
#define PDKIM_INPUT_SMTP    1
typedef struct pdkim_ctx {

  /* PDKIM_MODE_VERIFY or PDKIM_MODE_SIGN */
  int mode;

  /* PDKIM_INPUT_SMTP or PDKIM_INPUT_NORMAL */
  int input_mode;

  /* One (signing) or several chained (verification) signatures */
  pdkim_signature *sig;

  /* Callback for dns/txt query method (verification only) */
  int(*dns_txt_callback)(char *, char *);

  /* Coder's little helpers */
  pdkim_str *cur_header;
  char      *linebuf;
  int        linebuf_offset;
  int        seen_lf;
  int        seen_eod;
  int        past_headers;
  int        num_buffered_crlf;
  int        num_headers;
  pdkim_stringlist *headers; /* Raw headers for verification         */

#ifdef PDKIM_DEBUG
  /* A FILE pointer. When not NULL, debug output will be generated
    and sent to this stream */
  FILE *debug_stream;
#endif

} pdkim_ctx;


/* -------------------------------------------------------------------------- */
/* API functions. Please see the sample code in sample/test_sign.c and
   sample/test_verify.c for documentation.
*/

#ifdef __cplusplus
extern "C" {
#endif

DLLEXPORT
pdkim_ctx *pdkim_init_sign    (int, char *, char *, char *);

DLLEXPORT
pdkim_ctx *pdkim_init_verify  (int, int(*)(char *, char *));

DLLEXPORT
int        pdkim_set_optional (pdkim_ctx *, char *, char *,int, int,
                               long, int,
                               unsigned long,
                               unsigned long);

DLLEXPORT
int        pdkim_feed         (pdkim_ctx *, char *, int);
DLLEXPORT
int        pdkim_feed_finish  (pdkim_ctx *, pdkim_signature **);

DLLEXPORT
void       pdkim_free_ctx     (pdkim_ctx *);

#ifdef PDKIM_DEBUG
DLLEXPORT
void       pdkim_set_debug_stream(pdkim_ctx *, FILE *);
#endif

#ifdef __cplusplus
}
#endif
