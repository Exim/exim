/* $Cambridge: exim/src/src/pdkim/pdkim.h,v 1.1.2.5 2009/03/17 12:57:37 tom Exp $ */
/* pdkim.h */

#include "sha1.h"
#include "sha2.h"
#include "rsa.h"
#include "base64.h"

#define PDKIM_SIGNATURE_VERSION     "1"
#define PDKIM_PUB_RECORD_VERSION    "DKIM1"

#define PDKIM_MAX_HEADER_LEN        65536
#define PDKIM_MAX_HEADERS           512
#define PDKIM_MAX_BODY_LINE_LEN     1024
#define PDKIM_DNS_TXT_MAX_NAMELEN   1024
#define PDKIM_DNS_TXT_MAX_RECLEN    4096
#define PDKIM_DEBUG
#define PDKIM_DEFAULT_SIGN_HEADERS "From:Sender:Reply-To:Subject:Date:"\
                             "Message-ID:To:Cc:MIME-Version:Content-Type:"\
                             "Content-Transfer-Encoding:Content-ID:"\
                             "Content-Description:Resent-Date:Resent-From:"\
                             "Resent-Sender:Resent-To:Resent-Cc:"\
                             "Resent-Message-ID:In-Reply-To:References:"\
                             "List-Id:List-Help:List-Unsubscribe:"\
                             "List-Subscribe:List-Post:List-Owner:List-Archive"


/* Function success / error codes */
#define PDKIM_OK                      0
#define PDKIM_FAIL                   -1
#define PDKIM_ERR_OOM              -100
#define PDKIM_ERR_RSA_PRIVKEY      -101
#define PDKIM_ERR_RSA_SIGNING      -102
#define PDKIM_ERR_LONG_LINE        -103
#define PDKIM_ERR_BUFFER_TOO_SMALL -104

/* Main verification status */
#define PDKIM_VERIFY_NONE      0
#define PDKIM_VERIFY_INVALID   1
#define PDKIM_VERIFY_FAIL      2
#define PDKIM_VERIFY_PASS      3

/* Extended verification status */
#define PDKIM_VERIFY_FAIL_BODY    1
#define PDKIM_VERIFY_FAIL_MESSAGE 2

#define PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE 3
#define PDKIM_VERIFY_INVALID_BUFFER_SIZE        4
#define PDKIM_VERIFY_INVALID_PUBKEY_PARSING     5


#ifdef PDKIM_DEBUG
void pdkim_quoteprint(FILE *, char *, int, int);
#endif

typedef struct pdkim_stringlist {
  char *value;
  void *next;
} pdkim_stringlist;
pdkim_stringlist *pdkim_append_stringlist(pdkim_stringlist *, char *);


#define PDKIM_STR_ALLOC_FRAG 256
typedef struct pdkim_str {
  char         *str;
  unsigned int  len;
  unsigned int  allocated;
} pdkim_str;
pdkim_str *pdkim_strnew (char *);
char      *pdkim_strcat (pdkim_str *, char *);
char      *pdkim_strncat(pdkim_str *, char *, int);
void       pdkim_strfree(pdkim_str *);

#define PDKIM_QUERYMETHOD_DNS_TXT 0

#define PDKIM_ALGO_RSA_SHA256     0
#define PDKIM_ALGO_RSA_SHA1       1

#define PDKIM_CANON_SIMPLE        0
#define PDKIM_CANON_RELAXED       1

#define PDKIM_HASH_SHA256         0
#define PDKIM_HASH_SHA1           1

#define PDKIM_KEYTYPE_RSA         0


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

  /* (l=) Amount of hashed body bytes (after canonicalization) */
  unsigned long bodylength;

  /* (h=) Colon-separated list of header names that are included in the
     signature */
  char *headernames;

  /* (z=) */
  char *copiedheaders;

  /* (b=) Decoded raw signature data, along with its length in bytes */
  char *sigdata;
  int   sigdata_len;

  /* (bh=) Decoded raw body hash data, along with its length in bytes */
  char *bodyhash;
  int   bodyhash_len;

  /* The main verification status. One of:

     PDKIM_VERIFY_NONE      Verification was not attempted. This status
                            should not appear.

     PDKIM_VERIFY_INVALID   There was an error while trying to verify
                            the signature. A more precise description
                            is available in verify_ext_status.

     PDKIM_VERIFY_FAIL      Verification failed because either the body
                            hash did not match, or the signature verification
                            failed. This probably means the message was
                            modified. Check verify_ext_status for the
                            exact reason.

     PDKIM_VERIFY_PASS      Verification succeeded.
  */
  int verify_status;


  /* Extended verification status. Depending on the value of verify_status,
     it can contain:

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
        PDKIM_VERIFY_FAIL_MESSAGE


  */
  int verify_ext_status;



  pdkim_pubkey *pubkey;  /* Public key used to verify this signature.   */
  void *next;            /* Pointer to next signature in list.          */

  /* Per-signature helper variables ----------------------------------- */
  sha1_context sha1_body;
  sha2_context sha2_body;
  unsigned long signed_body_bytes;
  pdkim_stringlist *headers;
  /* Signing specific ------------------------------------------------- */
  char *rsa_privkey;     /* Private RSA key                             */
  char *sign_headers;    /* To-be-signed header names                   */
  /* Verification specific -------------------------------------------- */
  int headernames_pos;   /* Current position in header name list        */
  char *rawsig_no_b_val; /* Original signature header w/o b= tag value. */
} pdkim_signature;


/* -------------------------------------------------------------------------- */
/* Context to keep state between all operations */

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
  char       linebuf[PDKIM_MAX_BODY_LINE_LEN];
  int        linebuf_offset;
  int        seen_lf;
  int        seen_eod;
  int        past_headers;
  int        num_buffered_crlf;
  int        num_headers;

#ifdef PDKIM_DEBUG
  /* A FILE pointer. When not NULL, debug output will be generated
    and sent to this stream */
  FILE *debug_stream;
#endif

} pdkim_ctx;


int   header_name_match       (char *, char *, int);
char *pdkim_relax_header      (char *, int);

int   pdkim_update_bodyhash   (pdkim_ctx *, char *, int);
int   pdkim_finish_bodyhash   (pdkim_ctx *);

int   pdkim_bodyline_complete (pdkim_ctx *);
int   pdkim_header_complete   (pdkim_ctx *);

int   pdkim_feed              (pdkim_ctx *, char *, int);
int   pdkim_feed_finish       (pdkim_ctx *, char **);

char *pdkim_create_header     (pdkim_signature *, int);

pdkim_ctx
     *pdkim_init_sign         (int, char *, char *, char *);

pdkim_ctx
     *pdkim_init_verify       (int, int(*dns_txt_callback)(char *, char *));

int   pdkim_set_optional      (pdkim_ctx *,
                               char *, char *,
                               int, int,
                               unsigned long, int,
                               unsigned long,
                               unsigned long);

void  pdkim_free_pubkey       (pdkim_pubkey *);
void  pdkim_free_sig          (pdkim_signature *);
void  pdkim_free_ctx          (pdkim_ctx *);


#ifdef PDKIM_DEBUG
void  pdkim_set_debug_stream  (pdkim_ctx *, FILE *);
#endif
