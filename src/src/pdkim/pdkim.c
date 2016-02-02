/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2009 - 2016  Tom Kistner <tom@duncanthrax.net>
 *  Copyright (C) 2016  Jeremy Harris <jgh@exim.org>
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

#include "../exim.h"


#ifndef DISABLE_DKIM	/* entire file */

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif

#include "crypt_ver.h"

#ifdef RSA_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(RSA_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#include "pdkim.h"
#include "rsa.h"

#define PDKIM_SIGNATURE_VERSION     "1"
#define PDKIM_PUB_RECORD_VERSION    "DKIM1"

#define PDKIM_MAX_HEADER_LEN        65536
#define PDKIM_MAX_HEADERS           512
#define PDKIM_MAX_BODY_LINE_LEN     16384
#define PDKIM_DNS_TXT_MAX_NAMELEN   1024
#define PDKIM_DEFAULT_SIGN_HEADERS "From:Sender:Reply-To:Subject:Date:"\
                             "Message-ID:To:Cc:MIME-Version:Content-Type:"\
                             "Content-Transfer-Encoding:Content-ID:"\
                             "Content-Description:Resent-Date:Resent-From:"\
                             "Resent-Sender:Resent-To:Resent-Cc:"\
                             "Resent-Message-ID:In-Reply-To:References:"\
                             "List-Id:List-Help:List-Unsubscribe:"\
                             "List-Subscribe:List-Post:List-Owner:List-Archive"

/* -------------------------------------------------------------------------- */
struct pdkim_stringlist {
  char *value;
  int  tag;
  void *next;
};

#define PDKIM_STR_ALLOC_FRAG 256
struct pdkim_str {
  char         *str;
  unsigned int  len;
  unsigned int  allocated;
};

/* -------------------------------------------------------------------------- */
/* A bunch of list constants */
const char *pdkim_querymethods[] = {
  "dns/txt",
  NULL
};
const char *pdkim_algos[] = {
  "rsa-sha256",
  "rsa-sha1",
  NULL
};
const char *pdkim_canons[] = {
  "simple",
  "relaxed",
  NULL
};
const char *pdkim_hashes[] = {
  "sha256",
  "sha1",
  NULL
};
const char *pdkim_keytypes[] = {
  "rsa",
  NULL
};

typedef struct pdkim_combined_canon_entry {
  const char *str;
  int canon_headers;
  int canon_body;
} pdkim_combined_canon_entry;

pdkim_combined_canon_entry pdkim_combined_canons[] = {
  { "simple/simple",    PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { "simple/relaxed",   PDKIM_CANON_SIMPLE,   PDKIM_CANON_RELAXED },
  { "relaxed/simple",   PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { "relaxed/relaxed",  PDKIM_CANON_RELAXED,  PDKIM_CANON_RELAXED },
  { "simple",           PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { "relaxed",          PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { NULL,               0,                    0 }
};


/* -------------------------------------------------------------------------- */

const char *
pdkim_verify_status_str(int status)
{
  switch(status) {
    case PDKIM_VERIFY_NONE:    return "PDKIM_VERIFY_NONE";
    case PDKIM_VERIFY_INVALID: return "PDKIM_VERIFY_INVALID";
    case PDKIM_VERIFY_FAIL:    return "PDKIM_VERIFY_FAIL";
    case PDKIM_VERIFY_PASS:    return "PDKIM_VERIFY_PASS";
    default:                   return "PDKIM_VERIFY_UNKNOWN";
  }
}

const char *
pdkim_verify_ext_status_str(int ext_status)
{
  switch(ext_status) {
    case PDKIM_VERIFY_FAIL_BODY: return "PDKIM_VERIFY_FAIL_BODY";
    case PDKIM_VERIFY_FAIL_MESSAGE: return "PDKIM_VERIFY_FAIL_MESSAGE";
    case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE: return "PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE";
    case PDKIM_VERIFY_INVALID_BUFFER_SIZE: return "PDKIM_VERIFY_INVALID_BUFFER_SIZE";
    case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD: return "PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD";
    case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT: return "PDKIM_VERIFY_INVALID_PUBKEY_IMPORT";
    default: return "PDKIM_VERIFY_UNKNOWN";
  }
}


/* -------------------------------------------------------------------------- */
/* Print debugging functions */
static void
pdkim_quoteprint(const char *data, int len)
{
int i;
const unsigned char *p = (const unsigned char *)data;

for (i = 0; i < len; i++)
  {
  const int c = p[i];
  switch (c)
    {
    case ' ' : debug_printf("{SP}"); break;
    case '\t': debug_printf("{TB}"); break;
    case '\r': debug_printf("{CR}"); break;
    case '\n': debug_printf("{LF}"); break;
    case '{' : debug_printf("{BO}"); break;
    case '}' : debug_printf("{BC}"); break;
    default:
      if ( (c < 32) || (c > 127) )
	debug_printf("{%02x}", c);
      else
	debug_printf("%c", c);
      break;
    }
  }
debug_printf("\n");
}

static void
pdkim_hexprint(const char *data, int len)
{
int i;
const unsigned char *p = (const unsigned char *)data;

for (i = 0 ; i < len; i++)
  debug_printf("%02x", p[i]);
debug_printf("\n");
}



/* String package: should be replaced by Exim standard ones */

static pdkim_stringlist *
pdkim_prepend_stringlist(pdkim_stringlist *base, char *str)
{
pdkim_stringlist *new_entry = malloc(sizeof(pdkim_stringlist));

if (!new_entry) return NULL;
memset(new_entry, 0, sizeof(pdkim_stringlist));
if (!(new_entry->value = strdup(str))) return NULL;
if (base)
  {
  pdkim_stringlist *last = base;
  while (last->next != NULL) { last = last->next; }
  last->next = new_entry;
  return base;
  }
else
  return new_entry;
}


/* -------------------------------------------------------------------------- */
/* A small "growing string" implementation to escape malloc/realloc hell */

static pdkim_str *
pdkim_strnew (const char *cstr)
{
unsigned int len = cstr ? strlen(cstr) : 0;
pdkim_str *p = malloc(sizeof(pdkim_str));

if (!p) return NULL;
memset(p, 0, sizeof(pdkim_str));
if (!(p->str = malloc(len+1)))
  {
  free(p);
  return NULL;
  }
p->allocated = len+1;
p->len = len;
if (cstr)
  strcpy(p->str, cstr);
else
  p->str[p->len] = '\0';
return p;
}

static char *
pdkim_strncat(pdkim_str *str, const char *data, int len)
{
if ((str->allocated - str->len) < (len+1))
  {
  /* Extend the buffer */
  int num_frags = ((len+1)/PDKIM_STR_ALLOC_FRAG)+1;
  char *n = realloc(str->str,
		    (str->allocated+(num_frags*PDKIM_STR_ALLOC_FRAG)));
  if (n == NULL) return NULL;
  str->str = n;
  str->allocated += (num_frags*PDKIM_STR_ALLOC_FRAG);
  }
strncpy(&(str->str[str->len]), data, len);
str->len += len;
str->str[str->len] = '\0';
return str->str;
}

static char *
pdkim_strcat(pdkim_str *str, const char *cstr)
{
return pdkim_strncat(str, cstr, strlen(cstr));
}

static char *
pdkim_strtrim(pdkim_str *str)
{
char *p = str->str;
char *q = str->str;
while ( (*p != '\0') && ((*p == '\t') || (*p == ' ')) ) p++;
while (*p != '\0') {*q = *p; q++; p++;}
*q = '\0';
while ( (q != str->str) && ( (*q == '\0') || (*q == '\t') || (*q == ' ') ) )
  {
  *q = '\0';
  q--;
  }
str->len = strlen(str->str);
return str->str;
}

static char *
pdkim_strclear(pdkim_str *str)
{
str->str[0] = '\0';
str->len = 0;
return str->str;
}

static void
pdkim_strfree(pdkim_str *str)
{
if (!str) return;
if (str->str) free(str->str);
free(str);
}



/* -------------------------------------------------------------------------- */

static void
pdkim_free_pubkey(pdkim_pubkey *pub)
{
if (pub)
  {
  if (pub->version    ) free(pub->version);
  if (pub->granularity) free(pub->granularity);
  if (pub->hashes     ) free(pub->hashes);
  if (pub->keytype    ) free(pub->keytype);
  if (pub->srvtype    ) free(pub->srvtype);
  if (pub->notes      ) free(pub->notes);
  free(pub);
  }
}


/* -------------------------------------------------------------------------- */

static void
pdkim_free_sig(pdkim_signature *sig)
{
if (sig)
  {
  pdkim_signature *next = (pdkim_signature *)sig->next;

  pdkim_stringlist *e = sig->headers;
  while(e)
    {
    pdkim_stringlist *c = e;
    if (e->value) free(e->value);
    e = e->next;
    free(c);
    }

  if (sig->selector        ) free(sig->selector);
  if (sig->domain          ) free(sig->domain);
  if (sig->identity        ) free(sig->identity);
  if (sig->copiedheaders   ) free(sig->copiedheaders);
  if (sig->rsa_privkey     ) free(sig->rsa_privkey);
  if (sig->sign_headers    ) free(sig->sign_headers);
  if (sig->signature_header) free(sig->signature_header);

  if (sig->pubkey) pdkim_free_pubkey(sig->pubkey);

  free(sig);
  if (next) pdkim_free_sig(next);
  }
}


/* -------------------------------------------------------------------------- */

DLLEXPORT void
pdkim_free_ctx(pdkim_ctx *ctx)
{
if (ctx)
  {
  pdkim_stringlist *e = ctx->headers;
  while(e)
    {
    pdkim_stringlist *c = e;
    if (e->value) free(e->value);
    e = e->next;
    free(c);
    }
  pdkim_free_sig(ctx->sig);
  pdkim_strfree(ctx->cur_header);
  free(ctx);
  }
}


/* -------------------------------------------------------------------------- */
/* Matches the name of the passed raw "header" against
   the passed colon-separated "list", starting at entry
   "start". Returns the position of the header name in
   the list. */

static int
header_name_match(const char *header,
                      char       *tick,
                      int         do_tick)
{
char *hname;
char *lcopy;
char *p;
char *q;
int rc = PDKIM_FAIL;

/* Get header name */
char *hcolon = strchr(header, ':');

if (!hcolon) return rc; /* This isn't a header */

if (!(hname = malloc((hcolon-header)+1)))
  return PDKIM_ERR_OOM;
memset(hname, 0, (hcolon-header)+1);
strncpy(hname, header, (hcolon-header));

/* Copy tick-off list locally, so we can punch zeroes into it */
if (!(lcopy = strdup(tick)))
  {
  free(hname);
  return PDKIM_ERR_OOM;
  }
p = lcopy;
q = strchr(p, ':');
while (q)
  {
  *q = '\0';

  if (strcasecmp(p, hname) == 0)
    {
    rc = PDKIM_OK;
    /* Invalidate header name instance in tick-off list */
    if (do_tick) tick[p-lcopy] = '_';
    goto BAIL;
    }

  p = q+1;
  q = strchr(p, ':');
  }

if (strcasecmp(p, hname) == 0)
  {
  rc = PDKIM_OK;
  /* Invalidate header name instance in tick-off list */
  if (do_tick) tick[p-lcopy] = '_';
  }

BAIL:
free(hname);
free(lcopy);
return rc;
}


/* -------------------------------------------------------------------------- */
/* Performs "relaxed" canonicalization of a header. The returned pointer needs
   to be free()d. */

static char *
pdkim_relax_header (char *header, int crlf)
{
BOOL past_field_name = FALSE;
BOOL seen_wsp = FALSE;
char *p;
char *q;
char *relaxed = malloc(strlen(header)+3);

if (!relaxed) return NULL;

q = relaxed;
for (p = header; *p != '\0'; p++)
  {
  int c = *p;
  /* Ignore CR & LF */
  if (c == '\r' || c == '\n')
    continue;
  if (c == '\t' || c == ' ')
    {
    if (seen_wsp)
      continue;
    c = ' ';			/* Turns WSP into SP */
    seen_wsp = TRUE;
    }
  else
    if (!past_field_name && c == ':')
      {
      if (seen_wsp) q--;	/* This removes WSP before the colon */
      seen_wsp = TRUE;		/* This removes WSP after the colon */
      past_field_name = TRUE;
      }
    else
      seen_wsp = FALSE;

  /* Lowercase header name */
  if (!past_field_name) c = tolower(c);
  *q++ = c;
  }

if (q > relaxed && q[-1] == ' ') q--; /* Squash eventual trailing SP */
*q = '\0';

if (crlf) strcat(relaxed, "\r\n");
return relaxed;
}


/* -------------------------------------------------------------------------- */
#define PDKIM_QP_ERROR_DECODE -1

static char *
pdkim_decode_qp_char(char *qp_p, int *c)
{
char *initial_pos = qp_p;

/* Advance one char */
qp_p++;

/* Check for two hex digits and decode them */
if (isxdigit(*qp_p) && isxdigit(qp_p[1]))
  {
  /* Do hex conversion */
  *c = (isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10) << 4;
  *c |= isdigit(qp_p[1]) ? qp_p[1] - '0' : toupper(qp_p[1]) - 'A' + 10;
  return qp_p + 2;
  }

/* Illegal char here */
*c = PDKIM_QP_ERROR_DECODE;
return initial_pos;
}


/* -------------------------------------------------------------------------- */

static char *
pdkim_decode_qp(char *str)
{
int nchar = 0;
char *q;
char *p = str;
char *n = malloc(strlen(p)+1);

if (!n) return NULL;

*n = '\0';
q = n;
while (*p != '\0')
  {
  if (*p == '=')
    {
    p = pdkim_decode_qp_char(p, &nchar);
    if (nchar >= 0)
      {
      *q++ = nchar;
      continue;
      }
    }
  else
    *q++ = *p;
  p++;
  }
*q = '\0';
return n;
}


/* -------------------------------------------------------------------------- */

static void
pdkim_decode_base64(uschar *str, blob * b)
{
int dlen;
char *res;
dlen = b64decode(str, &b->data);
if (dlen < 0) b->data = NULL;
b->len = dlen;
}

/* -------------------------------------------------------------------------- */

static char *
pdkim_encode_base64(blob * b)
{
char * ret;
int old_pool = store_pool;

store_pool = POOL_PERM;
ret = CS b64encode(b->data, b->len);
store_pool = old_pool;
return ret;
}


/* -------------------------------------------------------------------------- */
#define PDKIM_HDR_LIMBO 0
#define PDKIM_HDR_TAG   1
#define PDKIM_HDR_VALUE 2

static pdkim_signature *
pdkim_parse_sig_header(pdkim_ctx *ctx, char *raw_hdr)
{
pdkim_signature *sig ;
char *p, *q;
pdkim_str *cur_tag = NULL;
pdkim_str *cur_val = NULL;
BOOL past_hname = FALSE;
BOOL in_b_val = FALSE;
int where = PDKIM_HDR_LIMBO;
int i;
int old_pool = store_pool;

/* There is a store-reset between header & body reception
so cannot use the main pool. Any allocs done by Exim
memory-handling must use the perm pool. */

store_pool = POOL_PERM;

if (!(sig = malloc(sizeof(pdkim_signature)))) return NULL;
memset(sig, 0, sizeof(pdkim_signature));
sig->bodylength = -1;

if (!(sig->rawsig_no_b_val = malloc(strlen(raw_hdr)+1)))
  {
  free(sig);
  return NULL;
  }

q = sig->rawsig_no_b_val;

for (p = raw_hdr; ; p++)
  {
  char c = *p;

  /* Ignore FWS */
  if (c == '\r' || c == '\n')
    goto NEXT_CHAR;

  /* Fast-forward through header name */
  if (!past_hname)
    {
    if (c == ':') past_hname = TRUE;
    goto NEXT_CHAR;
    }

  if (where == PDKIM_HDR_LIMBO)
    {
    /* In limbo, just wait for a tag-char to appear */
    if (!(c >= 'a' && c <= 'z'))
      goto NEXT_CHAR;

    where = PDKIM_HDR_TAG;
    }

  if (where == PDKIM_HDR_TAG)
    {
    if (!cur_tag)
      cur_tag = pdkim_strnew(NULL);

    if (c >= 'a' && c <= 'z')
      pdkim_strncat(cur_tag, p, 1);

    if (c == '=')
      {
      if (strcmp(cur_tag->str, "b") == 0)
        {
	*q = '='; q++;
	in_b_val = TRUE;
	}
      where = PDKIM_HDR_VALUE;
      goto NEXT_CHAR;
      }
    }

  if (where == PDKIM_HDR_VALUE)
    {
    if (!cur_val)
      cur_val = pdkim_strnew(NULL);

    if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
      goto NEXT_CHAR;

    if (c == ';' || c == '\0')
      {
      if (cur_tag->len > 0)
        {
	pdkim_strtrim(cur_val);

	DEBUG(D_acl) debug_printf(" %s=%s\n", cur_tag->str, cur_val->str);

	switch (cur_tag->str[0])
	  {
	  case 'b':
	    if (cur_tag->str[1] == 'h')
	      pdkim_decode_base64(US cur_val->str, &sig->bodyhash);
	    else
	      pdkim_decode_base64(US cur_val->str, &sig->sigdata);
	    break;
	  case 'v':
	      /* We only support version 1, and that is currently the
		 only version there is. */
	    if (strcmp(cur_val->str, PDKIM_SIGNATURE_VERSION) == 0)
	      sig->version = 1;
	    break;
	  case 'a':
	    for (i = 0; pdkim_algos[i]; i++)
	      if (strcmp(cur_val->str, pdkim_algos[i]) == 0)
	        {
		sig->algo = i;
		break;
		}
	    break;
	  case 'c':
	    for (i = 0; pdkim_combined_canons[i].str; i++)
	      if (strcmp(cur_val->str, pdkim_combined_canons[i].str) == 0)
	        {
		sig->canon_headers = pdkim_combined_canons[i].canon_headers;
		sig->canon_body    = pdkim_combined_canons[i].canon_body;
		break;
		}
	    break;
	  case 'q':
	    for (i = 0; pdkim_querymethods[i]; i++)
	      if (strcmp(cur_val->str, pdkim_querymethods[i]) == 0)
	        {
		sig->querymethod = i;
		break;
		}
	    break;
	  case 's':
	    sig->selector = strdup(cur_val->str); break;
	  case 'd':
	    sig->domain = strdup(cur_val->str); break;
	  case 'i':
	    sig->identity = pdkim_decode_qp(cur_val->str); break;
	  case 't':
	    sig->created = strtoul(cur_val->str, NULL, 10); break;
	  case 'x':
	    sig->expires = strtoul(cur_val->str, NULL, 10); break;
	  case 'l':
	    sig->bodylength = strtol(cur_val->str, NULL, 10); break;
	  case 'h':
	    sig->headernames = string_copy(cur_val->str); break;
	  case 'z':
	    sig->copiedheaders = pdkim_decode_qp(cur_val->str); break;
	  default:
	    DEBUG(D_acl) debug_printf(" Unknown tag encountered\n");
	    break;
	  }
	}
      pdkim_strclear(cur_tag);
      pdkim_strclear(cur_val);
      in_b_val = FALSE;
      where = PDKIM_HDR_LIMBO;
      }
    else
      pdkim_strncat(cur_val, p, 1);
    }

NEXT_CHAR:
  if (c == '\0')
    break;

  if (!in_b_val)
    *q++ = c;
  }

store_pool = old_pool;

/* Make sure the most important bits are there. */
if (!(sig->domain      && (*(sig->domain)      != '\0') &&
      sig->selector    && (*(sig->selector)    != '\0') &&
      sig->headernames && (*(sig->headernames) != '\0') &&
      sig->version))
  {
  pdkim_free_sig(sig);
  return NULL;
  }

*q = '\0';
/* Chomp raw header. The final newline must not be added to the signature. */
q--;
while (q > sig->rawsig_no_b_val  && (*q == '\r' || *q == '\n'))
  *q = '\0'; q--;	/*XXX questionable code layout; possible bug */

DEBUG(D_acl)
  {
  debug_printf(
	  "PDKIM >> Raw signature w/o b= tag value >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  pdkim_quoteprint(sig->rawsig_no_b_val, strlen(sig->rawsig_no_b_val));
  debug_printf(
	  "PDKIM >> Sig size: %4d bits\n", sig->sigdata.len*8);
  debug_printf(
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }

exim_sha_init(&sig->body_hash, sig->algo == PDKIM_ALGO_RSA_SHA1);
return sig;
}


/* -------------------------------------------------------------------------- */

static pdkim_pubkey *
pdkim_parse_pubkey_record(pdkim_ctx *ctx, char *raw_record)
{
pdkim_pubkey *pub;
char *p;
pdkim_str *cur_tag = NULL;
pdkim_str *cur_val = NULL;
int where = PDKIM_HDR_LIMBO;

if (!(pub = malloc(sizeof(pdkim_pubkey)))) return NULL;
memset(pub, 0, sizeof(pdkim_pubkey));

for (p = raw_record; ; p++)
  {
  char c = *p;

  /* Ignore FWS */
  if (c == '\r' || c == '\n')
    goto NEXT_CHAR;

  if (where == PDKIM_HDR_LIMBO)
    {
    /* In limbo, just wait for a tag-char to appear */
    if (!(c >= 'a' && c <= 'z'))
      goto NEXT_CHAR;

    where = PDKIM_HDR_TAG;
    }

  if (where == PDKIM_HDR_TAG)
    {
    if (!cur_tag)
      cur_tag = pdkim_strnew(NULL);

    if (c >= 'a' && c <= 'z')
      pdkim_strncat(cur_tag, p, 1);

    if (c == '=')
      {
      where = PDKIM_HDR_VALUE;
      goto NEXT_CHAR;
      }
    }

  if (where == PDKIM_HDR_VALUE)
    {
    if (!cur_val)
      cur_val = pdkim_strnew(NULL);

    if (c == '\r' || c == '\n')
      goto NEXT_CHAR;

    if (c == ';' || c == '\0')
      {
      if (cur_tag->len > 0)
        {
	pdkim_strtrim(cur_val);
	DEBUG(D_acl) debug_printf(" %s=%s\n", cur_tag->str, cur_val->str);

	switch (cur_tag->str[0])
	  {
	  case 'v':
	    /* This tag isn't evaluated because:
	       - We only support version DKIM1.
	       - Which is the default for this value (set below)
	       - Other versions are currently not specified.      */
	    break;
	  case 'h':
	    pub->hashes = strdup(cur_val->str); break;
	  case 'g':
	    pub->granularity = strdup(cur_val->str); break;
	  case 'n':
	    pub->notes = pdkim_decode_qp(cur_val->str); break;
	  case 'p':
	    pdkim_decode_base64(US cur_val->str, &pub->key);
            break;
	  case 'k':
	    pub->hashes = strdup(cur_val->str); break;
	  case 's':
	    pub->srvtype = strdup(cur_val->str); break;
	  case 't':
	    if (strchr(cur_val->str, 'y') != NULL) pub->testing = 1;
	    if (strchr(cur_val->str, 's') != NULL) pub->no_subdomaining = 1;
	    break;
	  default:
	    DEBUG(D_acl) debug_printf(" Unknown tag encountered\n");
	    break;
	  }
	}
      pdkim_strclear(cur_tag);
      pdkim_strclear(cur_val);
      where = PDKIM_HDR_LIMBO;
      }
    else
      pdkim_strncat(cur_val, p, 1);
    }

NEXT_CHAR:
  if (c == '\0') break;
  }

/* Set fallback defaults */
if (!pub->version    ) pub->version     = strdup(PDKIM_PUB_RECORD_VERSION);
if (!pub->granularity) pub->granularity = strdup("*");
if (!pub->keytype    ) pub->keytype     = strdup("rsa");
if (!pub->srvtype    ) pub->srvtype     = strdup("*");

/* p= is required */
if (pub->key.data)
  return pub;

pdkim_free_pubkey(pub);
return NULL;
}


/* -------------------------------------------------------------------------- */

static int
pdkim_update_bodyhash(pdkim_ctx *ctx, const char *data, int len)
{
pdkim_signature *sig = ctx->sig;
/* Cache relaxed version of data */
char *relaxed_data = NULL;
int   relaxed_len  = 0;

/* Traverse all signatures, updating their hashes. */
while (sig)
  {
  /* Defaults to simple canon (no further treatment necessary) */
  const char *canon_data = data;
  int         canon_len = len;

  if (sig->canon_body == PDKIM_CANON_RELAXED)
    {
    /* Relax the line if not done already */
    if (!relaxed_data)
      {
      BOOL seen_wsp = FALSE;
      const char *p;
      int q = 0;

      if (!(relaxed_data = malloc(len+1)))
	return PDKIM_ERR_OOM;

      for (p = data; *p; p++)
        {
	char c = *p;
	if (c == '\r')
	  {
	  if (q > 0 && relaxed_data[q-1] == ' ')
	    q--;
	  }
	else if (c == '\t' || c == ' ')
	  {
	  c = ' '; /* Turns WSP into SP */
	  if (seen_wsp)
	    continue;
	  seen_wsp = TRUE;
	  }
	else
	  seen_wsp = FALSE;
	relaxed_data[q++] = c;
	}
      relaxed_data[q] = '\0';
      relaxed_len = q;
      }
    canon_data = relaxed_data;
    canon_len  = relaxed_len;
    }

  /* Make sure we don't exceed the to-be-signed body length */
  if (  sig->bodylength >= 0
     && sig->signed_body_bytes + (unsigned long)canon_len > sig->bodylength
     )
    canon_len = sig->bodylength - sig->signed_body_bytes;

  if (canon_len > 0)
    {
    exim_sha_update(&sig->body_hash, canon_data, canon_len);
    sig->signed_body_bytes += canon_len;
    DEBUG(D_acl) pdkim_quoteprint(canon_data, canon_len);
    }

  sig = sig->next;
  }

if (relaxed_data) free(relaxed_data);
return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */

static int
pdkim_finish_bodyhash(pdkim_ctx *ctx)
{
pdkim_signature *sig;

/* Traverse all signatures */
for (sig = ctx->sig; sig; sig = sig->next)
  {					/* Finish hashes */
  blob bh;

  exim_sha_finish(&sig->body_hash, &bh);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] Body bytes hashed: %lu\n"
		 "PDKIM [%s] bh  computed: ",
		sig->domain, sig->signed_body_bytes, sig->domain);
    pdkim_hexprint(CS bh.data, bh.len);
    }

  /* SIGNING -------------------------------------------------------------- */
  if (ctx->mode == PDKIM_MODE_SIGN)
    {
    sig->bodyhash = bh;

    /* If bodylength limit is set, and we have received less bytes
       than the requested amount, effectively remove the limit tag. */
    if (sig->signed_body_bytes < sig->bodylength)
      sig->bodylength = -1;
    }

  /* VERIFICATION --------------------------------------------------------- */
  else
    {
    /* Compare bodyhash */
    if (memcmp(bh.data, sig->bodyhash.data, bh.len) == 0)
      {
      DEBUG(D_acl) debug_printf("PDKIM [%s] Body hash verified OK\n", sig->domain);
      }
    else
      {
      DEBUG(D_acl)
        {
	debug_printf("PDKIM [%s] bh signature: ", sig->domain);
	pdkim_hexprint(sig->bodyhash.data,
			 exim_sha_hashlen(&sig->body_hash));
	debug_printf("PDKIM [%s] Body hash did NOT verify\n", sig->domain);
	}
      sig->verify_status     = PDKIM_VERIFY_FAIL;
      sig->verify_ext_status = PDKIM_VERIFY_FAIL_BODY;
      }
    }
  }

return PDKIM_OK;
}



/* -------------------------------------------------------------------------- */
/* Callback from pdkim_feed below for processing complete body lines */

static int
pdkim_bodyline_complete(pdkim_ctx *ctx)
{
char *p = ctx->linebuf;
int   n = ctx->linebuf_offset;
pdkim_signature *sig = ctx->sig;	/*XXX assumes only one sig */

/* Ignore extra data if we've seen the end-of-data marker */
if (ctx->seen_eod) goto BAIL;

/* We've always got one extra byte to stuff a zero ... */
ctx->linebuf[ctx->linebuf_offset] = '\0';

/* Terminate on EOD marker */
if (memcmp(p, ".\r\n", 3) == 0)
  {
  /* In simple body mode, if any empty lines were buffered,
  replace with one. rfc 4871 3.4.3 */
  /*XXX checking the signed-body-bytes is a gross hack; I think
  it indicates that all linebreaks should be buffered, including
  the one terminating a text line */
  if (  sig && sig->canon_body == PDKIM_CANON_SIMPLE
     && sig->signed_body_bytes == 0
     && ctx->num_buffered_crlf > 0
     )
    pdkim_update_bodyhash(ctx, "\r\n", 2);

  ctx->seen_eod = TRUE;
  goto BAIL;
  }
/* Unstuff dots */
if (memcmp(p, "..", 2) == 0)
  {
  p++;
  n--;
  }

/* Empty lines need to be buffered until we find a non-empty line */
if (memcmp(p, "\r\n", 2) == 0)
  {
  ctx->num_buffered_crlf++;
  goto BAIL;
  }

if (sig && sig->canon_body == PDKIM_CANON_RELAXED)
  {
  /* Lines with just spaces need to be buffered too */
  char *check = p;
  while (memcmp(check, "\r\n", 2) != 0)
    {
    char c = *check;

    if (c != '\t' && c != ' ')
      goto PROCESS;
    check++;
    }

  ctx->num_buffered_crlf++;
  goto BAIL;
}

PROCESS:
/* At this point, we have a non-empty line, so release the buffered ones. */
while (ctx->num_buffered_crlf)
  {
  pdkim_update_bodyhash(ctx, "\r\n", 2);
  ctx->num_buffered_crlf--;
  }

pdkim_update_bodyhash(ctx, p, n);

BAIL:
ctx->linebuf_offset = 0;
return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */
/* Callback from pdkim_feed below for processing complete headers */
#define DKIM_SIGNATURE_HEADERNAME "DKIM-Signature:"

static int
pdkim_header_complete(pdkim_ctx *ctx)
{
/* Special case: The last header can have an extra \r appended */
if ( (ctx->cur_header->len > 1) &&
     (ctx->cur_header->str[(ctx->cur_header->len)-1] == '\r') )
  {
  ctx->cur_header->str[(ctx->cur_header->len)-1] = '\0';
  ctx->cur_header->len--;
  }

ctx->num_headers++;
if (ctx->num_headers > PDKIM_MAX_HEADERS) goto BAIL;

/* SIGNING -------------------------------------------------------------- */
if (ctx->mode == PDKIM_MODE_SIGN)
  {
  pdkim_signature *sig;

  for (sig = ctx->sig; sig; sig = sig->next)			/* Traverse all signatures */
    if (header_name_match(ctx->cur_header->str,
			  sig->sign_headers?
			    sig->sign_headers:
			    PDKIM_DEFAULT_SIGN_HEADERS, 0) == PDKIM_OK)
      {
      pdkim_stringlist *list;

      /* Add header to the signed headers list (in reverse order) */
      if (!(list = pdkim_prepend_stringlist(sig->headers,
				    ctx->cur_header->str)))
	return PDKIM_ERR_OOM;
      sig->headers = list;
      }
  }

/* VERIFICATION ----------------------------------------------------------- */
/* DKIM-Signature: headers are added to the verification list */
if (ctx->mode == PDKIM_MODE_VERIFY)
  {
  if (strncasecmp(ctx->cur_header->str,
		  DKIM_SIGNATURE_HEADERNAME,
		  strlen(DKIM_SIGNATURE_HEADERNAME)) == 0)
    {
    pdkim_signature *new_sig;

    /* Create and chain new signature block */
    DEBUG(D_acl) debug_printf(
	"PDKIM >> Found sig, trying to parse >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    if ((new_sig = pdkim_parse_sig_header(ctx, ctx->cur_header->str)))
      {
      pdkim_signature *last_sig = ctx->sig;
      if (!last_sig)
	ctx->sig = new_sig;
      else
        {
	while (last_sig->next) last_sig = last_sig->next;
	last_sig->next = new_sig;
	}
      }
    else
      DEBUG(D_acl) debug_printf(
	  "Error while parsing signature header\n"
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }

  /* every other header is stored for signature verification */
  else
    {
    pdkim_stringlist *list;

    if (!(list = pdkim_prepend_stringlist(ctx->headers, ctx->cur_header->str)))
      return PDKIM_ERR_OOM;
    ctx->headers = list;
    }
  }

BAIL:
pdkim_strclear(ctx->cur_header); /* Re-use existing pdkim_str */
return PDKIM_OK;
}



/* -------------------------------------------------------------------------- */
#define HEADER_BUFFER_FRAG_SIZE 256

DLLEXPORT int
pdkim_feed (pdkim_ctx *ctx, char *data, int len)
{
int p;

for (p = 0; p<len; p++)
  {
  char c = data[p];

  if (ctx->past_headers)
    {
    /* Processing body byte */
    ctx->linebuf[ctx->linebuf_offset++] = c;
    if (c == '\n')
      {
      int rc = pdkim_bodyline_complete(ctx); /* End of line */
      if (rc != PDKIM_OK) return rc;
      }
    if (ctx->linebuf_offset == (PDKIM_MAX_BODY_LINE_LEN-1))
      return PDKIM_ERR_LONG_LINE;
    }
  else
    {
    /* Processing header byte */
    if (c != '\r')
      {
      if (c == '\n')
        {
	if (ctx->seen_lf)
	  {
	  int rc = pdkim_header_complete(ctx); /* Seen last header line */
	  if (rc != PDKIM_OK) return rc;

	  ctx->past_headers = TRUE;
	  ctx->seen_lf = 0;
	  DEBUG(D_acl) debug_printf(
	      "PDKIM >> Hashed body data, canonicalized >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	  continue;
	  }
	else
	  ctx->seen_lf = TRUE;
	}
      else if (ctx->seen_lf)
        {
	if (!(c == '\t' || c == ' '))
	  {
	  int rc = pdkim_header_complete(ctx); /* End of header */
	  if (rc != PDKIM_OK) return rc;
	  }
	ctx->seen_lf = FALSE;
	}
      }

    if (!ctx->cur_header)
      if (!(ctx->cur_header = pdkim_strnew(NULL)))
	return PDKIM_ERR_OOM;

    if (ctx->cur_header->len < PDKIM_MAX_HEADER_LEN)
      if (!pdkim_strncat(ctx->cur_header, &data[p], 1))
	return PDKIM_ERR_OOM;
    }
  }
return PDKIM_OK;
}

/*
 * RFC 5322 specifies that header line length SHOULD be no more than 78
 * lets make it so!
 *  pdkim_headcat
 * returns char*
 *
 * col: this int holds and receives column number (octets since last '\n')
 * str: partial string to append to
 * pad: padding, split line or space after before or after eg: ";"
 * intro: - must join to payload eg "h=", usually the tag name
 * payload: eg base64 data - long data can be split arbitrarily.
 *
 * this code doesn't fold the header in some of the places that RFC4871
 * allows: As per RFC5322(2.2.3) it only folds before or after tag-value
 * pairs and inside long values. it also always spaces or breaks after the
 * "pad"
 *
 * no guarantees are made for output given out-of range input. like tag
 * names longer than 78, or bogus col. Input is assumed to be free of line breaks.
 */

static char *
pdkim_headcat(int *col, pdkim_str *str, const char * pad,
  const char *intro, const char *payload)
{
size_t l;

if (pad)
  {
  l = strlen(pad);
  if (*col + l > 78)
    {
    pdkim_strcat(str, "\r\n\t");
    *col = 1;
    }
  pdkim_strncat(str, pad, l);
  *col += l;
  }

l = (pad?1:0) + (intro?strlen(intro):0);

if (*col + l > 78)
  { /*can't fit intro - start a new line to make room.*/
  pdkim_strcat(str, "\r\n\t");
  *col = 1;
  l = intro?strlen(intro):0;
  }

l += payload ? strlen(payload):0 ;

while (l>77)
  { /* this fragment will not fit on a single line */
  if (pad)
    {
    pdkim_strcat(str, " ");
    *col += 1;
    pad = NULL; /* only want this once */
    l--;
    }

  if (intro)
    {
    size_t sl = strlen(intro);

    pdkim_strncat(str, intro, sl);
    *col += sl;
    l -= sl;
    intro = NULL; /* only want this once */
    }

  if (payload)
    {
    size_t sl = strlen(payload);
    size_t chomp = *col+sl < 77 ? sl : 78-*col;

    pdkim_strncat(str, payload, chomp);
    *col += chomp;
    payload += chomp;
    l -= chomp-1;
    }

  /* the while precondition tells us it didn't fit. */
  pdkim_strcat(str, "\r\n\t");
  *col = 1;
  }

if (*col + l > 78)
  {
  pdkim_strcat(str, "\r\n\t");
  *col = 1;
  pad = NULL;
  }

if (pad)
  {
  pdkim_strcat(str, " ");
  *col += 1;
  pad = NULL;
  }

if (intro)
  {
  size_t sl = strlen(intro);

  pdkim_strncat(str, intro, sl);
  *col += sl;
  l -= sl;
  intro = NULL;
  }

if (payload)
  {
  size_t sl = strlen(payload);

  pdkim_strncat(str, payload, sl);
  *col += sl;
  }

return str->str;
}


/* -------------------------------------------------------------------------- */

static char *
pdkim_create_header(pdkim_signature *sig, BOOL final)
{
char *rc = NULL;
char *base64_bh = NULL;
char *base64_b  = NULL;
int col = 0;
pdkim_str *hdr;
pdkim_str *canon_all;

if (!(hdr = pdkim_strnew("DKIM-Signature: v="PDKIM_SIGNATURE_VERSION)))
  return NULL;

if (!(canon_all = pdkim_strnew(pdkim_canons[sig->canon_headers])))
  goto BAIL;

if (!(base64_bh = pdkim_encode_base64(&sig->bodyhash)))
  goto BAIL;

col = strlen(hdr->str);

/* Required and static bits */
if (  pdkim_headcat(&col, hdr, ";", "a=", pdkim_algos[sig->algo])
   && pdkim_headcat(&col, hdr, ";", "q=", pdkim_querymethods[sig->querymethod])
   && pdkim_strcat(canon_all, "/")
   && pdkim_strcat(canon_all, pdkim_canons[sig->canon_body])
   && pdkim_headcat(&col, hdr, ";", "c=", canon_all->str)
   && pdkim_headcat(&col, hdr, ";", "d=", sig->domain)
   && pdkim_headcat(&col, hdr, ";", "s=", sig->selector)
   )
  {
  /* list of header names can be split between items. */
    {
    char *n = CS string_copy(sig->headernames);
    char *f = n;
    char *i = "h=";
    char *s = ";";

    if (!n) goto BAIL;
    while (*n)
      {
      char *c = strchr(n, ':');

      if (c) *c ='\0';

      if (!i)
	if (!pdkim_headcat(&col, hdr, NULL, NULL, ":"))
	  goto BAIL;

      if (!pdkim_headcat(&col, hdr, s, i, n))
	goto BAIL;

      if (!c)
        break;

      n = c+1;
      s = NULL;
      i = NULL;
      }
    }

  if(!pdkim_headcat(&col, hdr, ";", "bh=", base64_bh))
    goto BAIL;

  /* Optional bits */
  if (sig->identity)
    if(!pdkim_headcat(&col, hdr, ";", "i=", sig->identity))
      goto BAIL;

  if (sig->created > 0)
    {
    char minibuf[20];

    snprintf(minibuf, 20, "%lu", sig->created);
    if(!pdkim_headcat(&col, hdr, ";", "t=", minibuf))
      goto BAIL;
    }

  if (sig->expires > 0)
    {
    char minibuf[20];

    snprintf(minibuf, 20, "%lu", sig->expires);
    if(!pdkim_headcat(&col, hdr, ";", "x=", minibuf))
      goto BAIL;
    }

  if (sig->bodylength >= 0)
    {
    char minibuf[20];

    snprintf(minibuf, 20, "%lu", sig->bodylength);
    if(!pdkim_headcat(&col, hdr, ";", "l=", minibuf))
      goto BAIL;
    }

  /* Preliminary or final version? */
  if (final)
    {
    if (!(base64_b = pdkim_encode_base64(&sig->sigdata)))
      goto BAIL;
    if (!pdkim_headcat(&col, hdr, ";", "b=", base64_b))
      goto BAIL;
    }
  else 
    if(!pdkim_headcat(&col, hdr, ";", "b=", ""))
      goto BAIL;

  /* add trailing semicolon: I'm not sure if this is actually needed */
  if (!pdkim_headcat(&col, hdr, NULL, ";", ""))
    goto BAIL;
  }

rc = strdup(hdr->str);

BAIL:
pdkim_strfree(hdr);
if (canon_all) pdkim_strfree(canon_all);
return rc;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT int
pdkim_feed_finish(pdkim_ctx *ctx, pdkim_signature **return_signatures)
{
pdkim_signature *sig = ctx->sig;
pdkim_str *headernames = NULL;             /* Collected signed header names */

/* Check if we must still flush a (partial) header. If that is the
   case, the message has no body, and we must compute a body hash
   out of '<CR><LF>' */
if (ctx->cur_header && ctx->cur_header->len)
  {
  int rc = pdkim_header_complete(ctx);
  if (rc != PDKIM_OK) return rc;
  pdkim_update_bodyhash(ctx, "\r\n", 2);
  }
else
  DEBUG(D_acl) debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

/* Build (and/or evaluate) body hash */
if (pdkim_finish_bodyhash(ctx) != PDKIM_OK)
  return PDKIM_ERR_OOM;

/* SIGNING -------------------------------------------------------------- */
if (ctx->mode == PDKIM_MODE_SIGN)
  if (!(headernames = pdkim_strnew(NULL)))
    return PDKIM_ERR_OOM;
/* ---------------------------------------------------------------------- */

while (sig)
  {
  BOOL is_sha1 = sig->algo == PDKIM_ALGO_RSA_SHA1;
  hctx hhash_ctx;
  char * sig_hdr;
  blob hhash;
  blob hdata;
  int hdata_alloc = 0;

  hdata.data = NULL;
  hdata.len = 0;

  exim_sha_init(&hhash_ctx, is_sha1);

  DEBUG(D_acl) debug_printf(
      "PDKIM >> Hashed header data, canonicalized, in sequence >>>>>>>>>>>>>>\n");

  /* SIGNING ---------------------------------------------------------------- */
  /* When signing, walk through our header list and add them to the hash. As we
     go, construct a list of the header's names to use for the h= parameter. */

  if (ctx->mode == PDKIM_MODE_SIGN)
    {
    pdkim_stringlist *p;

    for (p = sig->headers; p; p = p->next)
      {
      uschar * rh;
      /* Collect header names (Note: colon presence is guaranteed here) */
      uschar * q = Ustrchr(p->value, ':');

      if (!(pdkim_strncat(headernames, p->value,
			(q-US (p->value)) + (p->next ? 1 : 0))))
	return PDKIM_ERR_OOM;

      rh = sig->canon_headers == PDKIM_CANON_RELAXED
	? US pdkim_relax_header(p->value, 1) /* cook header for relaxed canon */
	: string_copy(p->value);             /* just copy it for simple canon */
      if (!rh)
	return PDKIM_ERR_OOM;

      /* Feed header to the hash algorithm */
      exim_sha_update(&hhash_ctx, rh, strlen(rh));

      /* Remember headers block for signing (when the library cannot do incremental)  */
      (void) exim_rsa_data_append(&hdata, &hdata_alloc, rh);

      DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
      }
    }

  /* VERIFICATION ----------------------------------------------------------- */
  /* When verifying, walk through the header name list in the h= parameter and
     add the headers to the hash in that order. */
  else
    {
    uschar * b = string_copy(sig->headernames);
    uschar * p = b;
    uschar * q;
    pdkim_stringlist * hdrs;

    if (!b) return PDKIM_ERR_OOM;

    /* clear tags */
    for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
      hdrs->tag = 0;

    while(1)
      {
      if ((q = Ustrchr(p, ':')))
	*q = '\0';

      for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
	if (  hdrs->tag == 0
	   && strncasecmp(hdrs->value, CS p, Ustrlen(p)) == 0
	   && (hdrs->value)[Ustrlen(p)] == ':'
	   )
	  {
	  uschar * rh = sig->canon_headers == PDKIM_CANON_RELAXED
	    ? US pdkim_relax_header(hdrs->value, 1) /* cook header for relaxed canon */
	    : string_copy(hdrs->value);             /* just copy it for simple canon */
	  if (!rh)
	    return PDKIM_ERR_OOM;

	  /* Feed header to the hash algorithm */
	  exim_sha_update(&hhash_ctx, rh, strlen(rh));

	  DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
	  hdrs->tag = 1;
	  break;
	  }

      if (!q) break;
      p = q+1;
      }
    }

  DEBUG(D_acl) debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

  /* SIGNING ---------------------------------------------------------------- */
  if (ctx->mode == PDKIM_MODE_SIGN)
    {
    /* Copy headernames to signature struct */
    sig->headernames = string_copy(US headernames->str);
    pdkim_strfree(headernames);

    /* Create signature header with b= omitted */
    sig_hdr = pdkim_create_header(ctx->sig, FALSE);
    }

  /* VERIFICATION ----------------------------------------------------------- */
  else
    sig_hdr = strdup(sig->rawsig_no_b_val);
  /* ------------------------------------------------------------------------ */

  if (!sig_hdr)
    return PDKIM_ERR_OOM;

  /* Relax header if necessary */
  if (sig->canon_headers == PDKIM_CANON_RELAXED)
    {
    char *relaxed_hdr = pdkim_relax_header(sig_hdr, 0);

    free(sig_hdr);
    if (!relaxed_hdr)
      return PDKIM_ERR_OOM;
    sig_hdr = relaxed_hdr;
    }

  DEBUG(D_acl)
    {
    debug_printf(
	    "PDKIM >> Signed DKIM-Signature header, canonicalized >>>>>>>>>>>>>>>>>\n");
    pdkim_quoteprint(sig_hdr, strlen(sig_hdr));
    debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }

  /* Finalize header hash */
  exim_sha_update(&hhash_ctx, sig_hdr, strlen(sig_hdr));
  exim_sha_finish(&hhash_ctx, &hhash);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] hh computed: ", sig->domain);
    pdkim_hexprint(hhash.data, hhash.len);
    }

  /* Remember headers block for signing (when the library cannot do incremental)  */
  if (ctx->mode == PDKIM_MODE_SIGN)
    (void) exim_rsa_data_append(&hdata, &hdata_alloc, sig_hdr);

  free(sig_hdr);

  /* SIGNING ---------------------------------------------------------------- */
  if (ctx->mode == PDKIM_MODE_SIGN)
    {
    es_ctx sctx;
    const uschar * errstr;

    /* Import private key */
    if ((errstr = exim_rsa_signing_init(sig->rsa_privkey, &sctx)))
      {
      DEBUG(D_acl) debug_printf("signing_init: %s\n", errstr);
      return PDKIM_ERR_RSA_PRIVKEY;
      }

    /* Do signing.  With OpenSSL we are signing the hash of headers just
    calculated, with GnuTLS we have to sign an entire block of headers
    (due to available interfaces) and it recalculates the hash internally. */

#if defined(RSA_OPENSSL) || defined(RSA_GCRYPT)
    hdata = hhash;
#endif

    if ((errstr = exim_rsa_sign(&sctx, is_sha1, &hdata, &sig->sigdata)))
      {
      DEBUG(D_acl) debug_printf("signing: %s\n", errstr);
      return PDKIM_ERR_RSA_SIGNING;
      }

    DEBUG(D_acl)
      {
      debug_printf( "PDKIM [%s] b computed: ", sig->domain);
      pdkim_hexprint(sig->sigdata.data, sig->sigdata.len);
      }

    if (!(sig->signature_header = pdkim_create_header(ctx->sig, TRUE)))
      return PDKIM_ERR_OOM;
    }

  /* VERIFICATION ----------------------------------------------------------- */
  else
    {
    ev_ctx vctx;
    const uschar * errstr;

    char *dns_txt_name, *dns_txt_reply;

    /* Fetch public key for signing domain, from DNS */

    if (!(dns_txt_name  = malloc(PDKIM_DNS_TXT_MAX_NAMELEN)))
      return PDKIM_ERR_OOM;

    if (!(dns_txt_reply = malloc(PDKIM_DNS_TXT_MAX_RECLEN)))
      {
      free(dns_txt_name);
      return PDKIM_ERR_OOM;
      }

    memset(dns_txt_reply, 0, PDKIM_DNS_TXT_MAX_RECLEN);
    memset(dns_txt_name , 0, PDKIM_DNS_TXT_MAX_NAMELEN);

    if (snprintf(dns_txt_name, PDKIM_DNS_TXT_MAX_NAMELEN,
		 "%s._domainkey.%s.",
		 sig->selector, sig->domain) >= PDKIM_DNS_TXT_MAX_NAMELEN)
      {
      sig->verify_status =      PDKIM_VERIFY_INVALID;
      sig->verify_ext_status =  PDKIM_VERIFY_INVALID_BUFFER_SIZE;
      goto NEXT_VERIFY;
      }

    if (  ctx->dns_txt_callback(dns_txt_name, dns_txt_reply) != PDKIM_OK 
       || dns_txt_reply[0] == '\0')
      {
      sig->verify_status =      PDKIM_VERIFY_INVALID;
      sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE;
      goto NEXT_VERIFY;
      }

    DEBUG(D_acl)
      {
      debug_printf(
          "PDKIM >> Parsing public key record >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
          " Raw record: ");
      pdkim_quoteprint(dns_txt_reply, strlen(dns_txt_reply));
      }

    if (!(sig->pubkey = pdkim_parse_pubkey_record(ctx, dns_txt_reply)))
      {
      sig->verify_status =      PDKIM_VERIFY_INVALID;
      sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD;

      DEBUG(D_acl) debug_printf(
	  " Error while parsing public key record\n"
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      goto NEXT_VERIFY;
      }

    DEBUG(D_acl) debug_printf(
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

    /* Import public key */
    if ((errstr = exim_rsa_verify_init(&sig->pubkey->key, &vctx)))
      {
      DEBUG(D_acl) debug_printf("verify_init: %s\n", errstr);
      sig->verify_status =      PDKIM_VERIFY_INVALID;
      sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_IMPORT;
      goto NEXT_VERIFY;
      }

    /* Check the signature */
    if ((errstr = exim_rsa_verify(&vctx, is_sha1, &hhash, &sig->sigdata)))
      {
      DEBUG(D_acl) debug_printf("headers verify: %s\n", errstr);
      sig->verify_status =      PDKIM_VERIFY_FAIL;
      sig->verify_ext_status =  PDKIM_VERIFY_FAIL_MESSAGE;
      goto NEXT_VERIFY;
      }


    /* We have a winner! (if bodydhash was correct earlier) */
    if (sig->verify_status == PDKIM_VERIFY_NONE)
      sig->verify_status = PDKIM_VERIFY_PASS;

NEXT_VERIFY:

    DEBUG(D_acl)
      {
      debug_printf("PDKIM [%s] signature status: %s",
	      sig->domain, pdkim_verify_status_str(sig->verify_status));
      if (sig->verify_ext_status > 0)
	debug_printf(" (%s)\n",
		pdkim_verify_ext_status_str(sig->verify_ext_status));
      else
	debug_printf("\n");
      }

    free(dns_txt_name);
    free(dns_txt_reply);
    }

  sig = sig->next;
  }

/* If requested, set return pointer to signature(s) */
if (return_signatures)
  *return_signatures = ctx->sig;

return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT pdkim_ctx *
pdkim_init_verify(int(*dns_txt_callback)(char *, char *))
{
pdkim_ctx *ctx = malloc(sizeof(pdkim_ctx));

if (!ctx)
  return NULL;
memset(ctx, 0, sizeof(pdkim_ctx));

if (!(ctx->linebuf = malloc(PDKIM_MAX_BODY_LINE_LEN)))
  {
  free(ctx);
  return NULL;
  }

ctx->mode = PDKIM_MODE_VERIFY;
ctx->dns_txt_callback = dns_txt_callback;

return ctx;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT pdkim_ctx *
pdkim_init_sign(char *domain, char *selector, char *rsa_privkey, int algo)
{
pdkim_ctx *ctx;
pdkim_signature *sig;

if (!domain || !selector || !rsa_privkey)
  return NULL;

if (!(ctx = malloc(sizeof(pdkim_ctx))))
  return NULL;
memset(ctx, 0, sizeof(pdkim_ctx));

if (!(ctx->linebuf = malloc(PDKIM_MAX_BODY_LINE_LEN)))
  {
  free(ctx);
  return NULL;
  }

if (!(sig = malloc(sizeof(pdkim_signature))))
  {
  free(ctx->linebuf);
  free(ctx);
  return NULL;
  }
memset(sig, 0, sizeof(pdkim_signature));

sig->bodylength = -1;

ctx->mode = PDKIM_MODE_SIGN;
ctx->sig = sig;

sig->domain = strdup(domain);
sig->selector = strdup(selector);
sig->rsa_privkey = strdup(rsa_privkey);
sig->algo = algo;

if (!sig->domain || !sig->selector || !sig->rsa_privkey)
  goto BAIL;

exim_sha_init(&sig->body_hash, algo == PDKIM_ALGO_RSA_SHA1);
return ctx;

BAIL:
  pdkim_free_ctx(ctx);
  return NULL;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT int
pdkim_set_optional(pdkim_ctx *ctx,
                       char *sign_headers,
                       char *identity,
                       int canon_headers,
                       int canon_body,
                       long bodylength,
                       unsigned long created,
                       unsigned long expires)
{
if (identity)
  if (!(ctx->sig->identity = strdup(identity)))
    return PDKIM_ERR_OOM;

if (sign_headers)
  if (!(ctx->sig->sign_headers = strdup(sign_headers)))
    return PDKIM_ERR_OOM;

ctx->sig->canon_headers = canon_headers;
ctx->sig->canon_body = canon_body;
ctx->sig->bodylength = bodylength;
ctx->sig->created = created;
ctx->sig->expires = expires;

return PDKIM_OK;
}


void
pdkim_init(void)
{
exim_rsa_init();
}



#endif	/*DISABLE_DKIM*/
