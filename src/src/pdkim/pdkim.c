/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2009 - 2016  Tom Kistner <tom@duncanthrax.net>
 *  Copyright (C) 2016 - 2017  Jeremy Harris <jgh@exim.org>
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

#ifdef SIGN_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(SIGN_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#include "pdkim.h"
#include "signing.h"

#define PDKIM_SIGNATURE_VERSION     "1"
#define PDKIM_PUB_RECORD_VERSION    US "DKIM1"

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
  uschar * value;
  int      tag;
  void *   next;
};

/* -------------------------------------------------------------------------- */
/* A bunch of list constants */
const uschar * pdkim_querymethods[] = {
  US"dns/txt",
  NULL
};
const uschar * pdkim_canons[] = {
  US"simple",
  US"relaxed",
  NULL
};

typedef struct {
  const uschar * dkim_hashname;
  hashmethod	 exim_hashmethod;
} pdkim_hashtype;
static const pdkim_hashtype pdkim_hashes[] = {
  { US"sha1",   HASH_SHA1 },
  { US"sha256", HASH_SHA2_256 },
  { US"sha512", HASH_SHA2_512 }
};

const uschar * pdkim_keytypes[] = {
  US"rsa"
};

typedef struct pdkim_combined_canon_entry {
  const uschar * str;
  int canon_headers;
  int canon_body;
} pdkim_combined_canon_entry;

pdkim_combined_canon_entry pdkim_combined_canons[] = {
  { US"simple/simple",    PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { US"simple/relaxed",   PDKIM_CANON_SIMPLE,   PDKIM_CANON_RELAXED },
  { US"relaxed/simple",   PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { US"relaxed/relaxed",  PDKIM_CANON_RELAXED,  PDKIM_CANON_RELAXED },
  { US"simple",           PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { US"relaxed",          PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { NULL,                 0,                    0 }
};


/* -------------------------------------------------------------------------- */
uschar *
dkim_sig_to_a_tag(pdkim_signature * sig)
{
if (  sig->keytype < 0  || sig->keytype > nelem(pdkim_keytypes)
   || sig->hashtype < 0 || sig->hashtype > nelem(pdkim_hashes))
  return US"err";
return string_sprintf("%s-%s",
  pdkim_keytypes[sig->keytype], pdkim_hashes[sig->hashtype].dkim_hashname);
}



const char *
pdkim_verify_status_str(int status)
{
switch(status)
  {
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
switch(ext_status)
  {
  case PDKIM_VERIFY_FAIL_BODY: return "PDKIM_VERIFY_FAIL_BODY";
  case PDKIM_VERIFY_FAIL_MESSAGE: return "PDKIM_VERIFY_FAIL_MESSAGE";
  case PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH: return "PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH";
  case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE: return "PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE";
  case PDKIM_VERIFY_INVALID_BUFFER_SIZE: return "PDKIM_VERIFY_INVALID_BUFFER_SIZE";
  case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD: return "PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD";
  case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT: return "PDKIM_VERIFY_INVALID_PUBKEY_IMPORT";
  case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR: return "PDKIM_VERIFY_INVALID_SIGNATURE_ERROR";
  case PDKIM_VERIFY_INVALID_DKIM_VERSION: return "PDKIM_VERIFY_INVALID_DKIM_VERSION";
  default: return "PDKIM_VERIFY_UNKNOWN";
  }
}

const uschar *
pdkim_errstr(int status)
{
switch(status)
  {
  case PDKIM_OK:		return US"OK";
  case PDKIM_FAIL:		return US"FAIL";
  case PDKIM_ERR_RSA_PRIVKEY:	return US"RSA_PRIVKEY";
  case PDKIM_ERR_RSA_SIGNING:	return US"RSA SIGNING";
  case PDKIM_ERR_LONG_LINE:	return US"RSA_LONG_LINE";
  case PDKIM_ERR_BUFFER_TOO_SMALL:	return US"BUFFER_TOO_SMALL";
  case PDKIM_SIGN_PRIVKEY_WRAP:	return US"PRIVKEY_WRAP";
  case PDKIM_SIGN_PRIVKEY_B64D:	return US"PRIVKEY_B64D";
  default: return US"(unknown)";
  }
}


/* -------------------------------------------------------------------------- */
/* Print debugging functions */
static void
pdkim_quoteprint(const uschar *data, int len)
{
int i;
for (i = 0; i < len; i++)
  {
  const int c = data[i];
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
pdkim_hexprint(const uschar *data, int len)
{
int i;
if (data) for (i = 0 ; i < len; i++) debug_printf("%02x", data[i]);
else debug_printf("<NULL>");
debug_printf("\n");
}



static pdkim_stringlist *
pdkim_prepend_stringlist(pdkim_stringlist * base, const uschar * str)
{
pdkim_stringlist * new_entry = store_get(sizeof(pdkim_stringlist));

memset(new_entry, 0, sizeof(pdkim_stringlist));
new_entry->value = string_copy(str);
if (base) new_entry->next = base;
return new_entry;
}



/* Trim whitespace fore & aft */

static void
pdkim_strtrim(uschar * str)
{
uschar * p = str;
uschar * q = str;
while (*p == '\t' || *p == ' ') p++;		/* skip whitespace */
while (*p) {*q = *p; q++; p++;}			/* dump the leading whitespace */
*q = '\0';
while (q != str && ( (*q == '\0') || (*q == '\t') || (*q == ' ') ) )
  {						/* dump trailing whitespace */
  *q = '\0';
  q--;
  }
}



/* -------------------------------------------------------------------------- */

DLLEXPORT void
pdkim_free_ctx(pdkim_ctx *ctx)
{
}


/* -------------------------------------------------------------------------- */
/* Matches the name of the passed raw "header" against
   the passed colon-separated "tick", and invalidates
   the entry in tick. Returns OK or fail-code */
/*XXX might be safer done using a pdkim_stringlist for "tick" */

static int
header_name_match(const uschar * header, uschar * tick)
{
uschar * hname;
uschar * lcopy;
uschar * p;
uschar * q;
uschar * hcolon = Ustrchr(header, ':');		/* Get header name */

if (!hcolon)
  return PDKIM_FAIL; /* This isn't a header */

/* if we had strncmpic() we wouldn't need this copy */
hname = string_copyn(header, hcolon-header);

/* Copy tick-off list locally, so we can punch zeroes into it */
p = lcopy = string_copy(tick);

for (q = Ustrchr(p, ':'); q; q = Ustrchr(p, ':'))
  {
  *q = '\0';
  if (strcmpic(p, hname) == 0)
    goto found;

  p = q+1;
  }

if (strcmpic(p, hname) == 0)
  goto found;

return PDKIM_FAIL;

found:
  /* Invalidate header name instance in tick-off list */
  tick[p-lcopy] = '_';
  return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */
/* Performs "relaxed" canonicalization of a header. */

static uschar *
pdkim_relax_header(const uschar * header, BOOL append_crlf)
{
BOOL past_field_name = FALSE;
BOOL seen_wsp = FALSE;
const uschar * p;
uschar * relaxed = store_get(Ustrlen(header)+3);
uschar * q = relaxed;

for (p = header; *p; p++)
  {
  uschar c = *p;

  if (c == '\r' || c == '\n')	/* Ignore CR & LF */
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
      if (seen_wsp) q--;	/* This removes WSP immediately before the colon */
      seen_wsp = TRUE;		/* This removes WSP immediately after the colon */
      past_field_name = TRUE;
      }
    else
      seen_wsp = FALSE;

  /* Lowercase header name */
  if (!past_field_name) c = tolower(c);
  *q++ = c;
  }

if (q > relaxed && q[-1] == ' ') q--; /* Squash eventual trailing SP */

if (append_crlf) { *q++ = '\r'; *q++ = '\n'; }
*q = '\0';
return relaxed;
}


/* -------------------------------------------------------------------------- */
#define PDKIM_QP_ERROR_DECODE -1

static const uschar *
pdkim_decode_qp_char(const uschar *qp_p, int *c)
{
const uschar *initial_pos = qp_p;

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

static uschar *
pdkim_decode_qp(const uschar * str)
{
int nchar = 0;
uschar * q;
const uschar * p = str;
uschar * n = store_get(Ustrlen(str)+1);

*n = '\0';
q = n;
while (*p)
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
pdkim_decode_base64(const uschar * str, blob * b)
{
int dlen;
dlen = b64decode(str, &b->data);
if (dlen < 0) b->data = NULL;
b->len = dlen;
}

static uschar *
pdkim_encode_base64(blob * b)
{
return b64encode(b->data, b->len);
}


/* -------------------------------------------------------------------------- */
#define PDKIM_HDR_LIMBO 0
#define PDKIM_HDR_TAG   1
#define PDKIM_HDR_VALUE 2

static pdkim_signature *
pdkim_parse_sig_header(pdkim_ctx *ctx, uschar * raw_hdr)
{
pdkim_signature * sig;
uschar *p, *q;
uschar * cur_tag = NULL; int ts = 0, tl = 0;
uschar * cur_val = NULL; int vs = 0, vl = 0;
BOOL past_hname = FALSE;
BOOL in_b_val = FALSE;
int where = PDKIM_HDR_LIMBO;
int i;

sig = store_get(sizeof(pdkim_signature));
memset(sig, 0, sizeof(pdkim_signature));
sig->bodylength = -1;

/* Set so invalid/missing data error display is accurate */
sig->version = 0;
sig->keytype = -1;
sig->hashtype = -1;

q = sig->rawsig_no_b_val = store_get(Ustrlen(raw_hdr)+1);

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
    if (c >= 'a' && c <= 'z')
      cur_tag = string_catn(cur_tag, &ts, &tl, p, 1);

    if (c == '=')
      {
      cur_tag[tl] = '\0';
      if (Ustrcmp(cur_tag, "b") == 0)
        {
	*q++ = '=';
	in_b_val = TRUE;
	}
      where = PDKIM_HDR_VALUE;
      goto NEXT_CHAR;
      }
    }

  if (where == PDKIM_HDR_VALUE)
    {
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
      goto NEXT_CHAR;

    if (c == ';' || c == '\0')
      {
      if (tl && vl)
        {
	cur_val[vl] = '\0';
	pdkim_strtrim(cur_val);

	DEBUG(D_acl) debug_printf(" %s=%s\n", cur_tag, cur_val);

	switch (*cur_tag)
	  {
	  case 'b':
	    pdkim_decode_base64(cur_val,
			    cur_tag[1] == 'h' ? &sig->bodyhash : &sig->sighash);
	    break;
	  case 'v':
	      /* We only support version 1, and that is currently the
		 only version there is. */
	    sig->version =
	      Ustrcmp(cur_val, PDKIM_SIGNATURE_VERSION) == 0 ? 1 : -1;
	    break;
	  case 'a':
	    {
	    uschar * s = Ustrchr(cur_val, '-');

	    for(i = 0; i < nelem(pdkim_keytypes); i++)
	      if (Ustrncmp(cur_val, pdkim_keytypes[i], s - cur_val) == 0)
		{ sig->keytype = i; break; }
	    for (++s, i = 0; i < nelem(pdkim_hashes); i++)
	      if (Ustrcmp(s, pdkim_hashes[i].dkim_hashname) == 0)
		{ sig->hashtype = i; break; }
	    break;
	    }

	  case 'c':
	    for (i = 0; pdkim_combined_canons[i].str; i++)
	      if (Ustrcmp(cur_val, pdkim_combined_canons[i].str) == 0)
	        {
		sig->canon_headers = pdkim_combined_canons[i].canon_headers;
		sig->canon_body    = pdkim_combined_canons[i].canon_body;
		break;
		}
	    break;
	  case 'q':
	    for (i = 0; pdkim_querymethods[i]; i++)
	      if (Ustrcmp(cur_val, pdkim_querymethods[i]) == 0)
	        {
		sig->querymethod = i;
		break;
		}
	    break;
	  case 's':
	    sig->selector = string_copy(cur_val); break;
	  case 'd':
	    sig->domain = string_copy(cur_val); break;
	  case 'i':
	    sig->identity = pdkim_decode_qp(cur_val); break;
	  case 't':
	    sig->created = strtoul(CS cur_val, NULL, 10); break;
	  case 'x':
	    sig->expires = strtoul(CS cur_val, NULL, 10); break;
	  case 'l':
	    sig->bodylength = strtol(CS cur_val, NULL, 10); break;
	  case 'h':
	    sig->headernames = string_copy(cur_val); break;
	  case 'z':
	    sig->copiedheaders = pdkim_decode_qp(cur_val); break;
	  default:
	    DEBUG(D_acl) debug_printf(" Unknown tag encountered\n");
	    break;
	  }
	}
      tl = 0;
      vl = 0;
      in_b_val = FALSE;
      where = PDKIM_HDR_LIMBO;
      }
    else
      cur_val = string_catn(cur_val, &vs, &vl, p, 1);
    }

NEXT_CHAR:
  if (c == '\0')
    break;

  if (!in_b_val)
    *q++ = c;
  }

*q = '\0';
/* Chomp raw header. The final newline must not be added to the signature. */
while (--q > sig->rawsig_no_b_val  && (*q == '\r' || *q == '\n'))
  *q = '\0';

DEBUG(D_acl)
  {
  debug_printf(
	  "PDKIM >> Raw signature w/o b= tag value >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  pdkim_quoteprint(US sig->rawsig_no_b_val, Ustrlen(sig->rawsig_no_b_val));
  debug_printf(
	  "PDKIM >> Sig size: %4u bits\n", (unsigned) sig->sighash.len*8);
  debug_printf(
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }

/*XXX hash method: extend for sha512 */
if (!exim_sha_init(&sig->body_hash_ctx,
	       pdkim_hashes[sig->hashtype].exim_hashmethod))
  {
  DEBUG(D_acl)
    debug_printf("PDKIM: hash init error, possibly nonhandled hashtype\n");
  return NULL;
  }
return sig;
}


/* -------------------------------------------------------------------------- */

static pdkim_pubkey *
pdkim_parse_pubkey_record(pdkim_ctx *ctx, const uschar *raw_record)
{
const uschar * ele;
int sep = ';';
pdkim_pubkey * pub;

pub = store_get(sizeof(pdkim_pubkey));
memset(pub, 0, sizeof(pdkim_pubkey));

while ((ele = string_nextinlist(&raw_record, &sep, NULL, 0)))
  {
  const uschar * val;

  if ((val = Ustrchr(ele, '=')))
    {
    int taglen = val++ - ele;

    DEBUG(D_acl) debug_printf(" %.*s=%s\n", taglen, ele, val);
    switch (ele[0])
      {
      case 'v': pub->version = val;			break;
      case 'h': pub->hashes = val;			break;
      case 'k': break;
      case 'g': pub->granularity = val;			break;
      case 'n': pub->notes = pdkim_decode_qp(val);	break;
      case 'p': pdkim_decode_base64(val, &pub->key);	break;
      case 's': pub->srvtype = val;			break;
      case 't': if (Ustrchr(val, 'y')) pub->testing = 1;
		if (Ustrchr(val, 's')) pub->no_subdomaining = 1;
		break;
      default:  DEBUG(D_acl) debug_printf(" Unknown tag encountered\n"); break;
      }
    }
  }

/* Set fallback defaults */
if (!pub->version    ) pub->version     = string_copy(PDKIM_PUB_RECORD_VERSION);
else if (Ustrcmp(pub->version, PDKIM_PUB_RECORD_VERSION) != 0)
  {
  DEBUG(D_acl) debug_printf(" Bad v= field\n");
  return NULL;
  }

if (!pub->granularity) pub->granularity = US"*";
/*
if (!pub->keytype    ) pub->keytype     = US"rsa";
*/
if (!pub->srvtype    ) pub->srvtype     = US"*";

/* p= is required */
if (pub->key.data)
  return pub;

DEBUG(D_acl) debug_printf(" Missing p= field\n");
return NULL;
}


/* -------------------------------------------------------------------------- */

static int
pdkim_update_bodyhash(pdkim_ctx * ctx, const char * data, int len)
{
pdkim_signature * sig;
uschar * relaxed_data = NULL;	/* Cache relaxed version of data */
int relaxed_len = 0;

/* Traverse all signatures, updating their hashes. */
for (sig = ctx->sig; sig; sig = sig->next)
  {
  /* Defaults to simple canon (no further treatment necessary) */
  const uschar *canon_data = CUS data;
  int           canon_len = len;

  if (sig->canon_body == PDKIM_CANON_RELAXED)
    {
    /* Relax the line if not done already */
    if (!relaxed_data)
      {
      BOOL seen_wsp = FALSE;
      const char *p;
      int q = 0;

      /* We want to be able to free this else we allocate
      for the entire message which could be many MB. Since
      we don't know what allocations the SHA routines might
      do, not safe to use store_get()/store_reset(). */

      relaxed_data = store_malloc(len+1);

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
    exim_sha_update(&sig->body_hash_ctx, CUS canon_data, canon_len);
    sig->signed_body_bytes += canon_len;
    DEBUG(D_acl) pdkim_quoteprint(canon_data, canon_len);
    }
  }

if (relaxed_data) store_free(relaxed_data);
return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */

static void
pdkim_finish_bodyhash(pdkim_ctx *ctx)
{
pdkim_signature *sig;

/* Traverse all signatures */
for (sig = ctx->sig; sig; sig = sig->next)
  {					/* Finish hashes */
  blob bh;

  exim_sha_finish(&sig->body_hash_ctx, &bh);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] Body bytes hashed: %lu\n"
		 "PDKIM [%s] Body hash computed: ",
		sig->domain, sig->signed_body_bytes, sig->domain);
    pdkim_hexprint(CUS bh.data, bh.len);
    }

  /* SIGNING -------------------------------------------------------------- */
  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    sig->bodyhash = bh;

    /* If bodylength limit is set, and we have received less bytes
       than the requested amount, effectively remove the limit tag. */
    if (sig->signed_body_bytes < sig->bodylength)
      sig->bodylength = -1;
    }

  else
  /* VERIFICATION --------------------------------------------------------- */
  /* Be careful that the header sig included a bodyash */

    if (sig->bodyhash.data && memcmp(bh.data, sig->bodyhash.data, bh.len) == 0)
      {
      DEBUG(D_acl) debug_printf("PDKIM [%s] Body hash verified OK\n", sig->domain);
      }
    else
      {
      DEBUG(D_acl)
        {
	debug_printf("PDKIM [%s] Body hash signature from headers: ", sig->domain);
	pdkim_hexprint(sig->bodyhash.data, sig->bodyhash.len);
	debug_printf("PDKIM [%s] Body hash did NOT verify\n", sig->domain);
	}
      sig->verify_status     = PDKIM_VERIFY_FAIL;
      sig->verify_ext_status = PDKIM_VERIFY_FAIL_BODY;
      }
  }
}



static int
pdkim_body_complete(pdkim_ctx * ctx)
{
pdkim_signature * sig = ctx->sig;	/*XXX assumes only one sig */

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

ctx->flags |= PDKIM_SEEN_EOD;
ctx->linebuf_offset = 0;
return PDKIM_OK;
}



/* -------------------------------------------------------------------------- */
/* Call from pdkim_feed below for processing complete body lines */

static int
pdkim_bodyline_complete(pdkim_ctx *ctx)
{
char *p = ctx->linebuf;
int   n = ctx->linebuf_offset;
pdkim_signature *sig = ctx->sig;	/*XXX assumes only one sig */

/* Ignore extra data if we've seen the end-of-data marker */
if (ctx->flags & PDKIM_SEEN_EOD) goto BAIL;

/* We've always got one extra byte to stuff a zero ... */
ctx->linebuf[ctx->linebuf_offset] = '\0';

/* Terminate on EOD marker */
if (ctx->flags & PDKIM_DOT_TERM)
  {
  if (memcmp(p, ".\r\n", 3) == 0)
    return pdkim_body_complete(ctx);

  /* Unstuff dots */
  if (memcmp(p, "..", 2) == 0)
    {
    p++;
    n--;
    }
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
pdkim_header_complete(pdkim_ctx * ctx)
{
pdkim_signature * sig, * last_sig;

/* Special case: The last header can have an extra \r appended */
if ( (ctx->cur_header_len > 1) &&
     (ctx->cur_header[(ctx->cur_header_len)-1] == '\r') )
  --ctx->cur_header_len;
ctx->cur_header[ctx->cur_header_len] = '\0';

if (++ctx->num_headers > PDKIM_MAX_HEADERS) goto BAIL;

/* SIGNING -------------------------------------------------------------- */
if (ctx->flags & PDKIM_MODE_SIGN)
  for (sig = ctx->sig; sig; sig = sig->next)			/* Traverse all signatures */

    /* Add header to the signed headers list (in reverse order) */
    sig->headers = pdkim_prepend_stringlist(sig->headers,
				  ctx->cur_header);

/* VERIFICATION ----------------------------------------------------------- */
/* DKIM-Signature: headers are added to the verification list */
else
  {
#ifdef notdef
  DEBUG(D_acl)
    {
    debug_printf("PDKIM >> raw hdr: ");
    pdkim_quoteprint(CUS ctx->cur_header, ctx->cur_header_len);
    }
#endif
  if (strncasecmp(CCS ctx->cur_header,
		  DKIM_SIGNATURE_HEADERNAME,
		  Ustrlen(DKIM_SIGNATURE_HEADERNAME)) == 0)
    {
    /* Create and chain new signature block.  We could error-check for all
    required tags here, but prefer to create the internal sig and expicitly
    fail verification of it later. */

    DEBUG(D_acl) debug_printf(
	"PDKIM >> Found sig, trying to parse >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    sig = pdkim_parse_sig_header(ctx, ctx->cur_header);

    if (!(last_sig = ctx->sig))
      ctx->sig = sig;
    else
      {
      while (last_sig->next) last_sig = last_sig->next;
      last_sig->next = sig;
      }
    }

  /* all headers are stored for signature verification */
  ctx->headers = pdkim_prepend_stringlist(ctx->headers, ctx->cur_header);
  }

BAIL:
ctx->cur_header[ctx->cur_header_len = 0] = '\0';	/* leave buffer for reuse */
return PDKIM_OK;
}



/* -------------------------------------------------------------------------- */
#define HEADER_BUFFER_FRAG_SIZE 256

DLLEXPORT int
pdkim_feed(pdkim_ctx * ctx, uschar * data, int len)
{
int p, rc;

/* Alternate EOD signal, used in non-dotstuffing mode */
if (!data)
  pdkim_body_complete(ctx);

else for (p = 0; p<len; p++)
  {
  uschar c = data[p];

  if (ctx->flags & PDKIM_PAST_HDRS)
    {
    if (c == '\n' && !(ctx->flags & PDKIM_SEEN_CR))	/* emulate the CR */
      {
      ctx->linebuf[ctx->linebuf_offset++] = '\r';
      if (ctx->linebuf_offset == PDKIM_MAX_BODY_LINE_LEN-1)
	return PDKIM_ERR_LONG_LINE;
      }

    /* Processing body byte */
    ctx->linebuf[ctx->linebuf_offset++] = c;
    if (c == '\r')
      ctx->flags |= PDKIM_SEEN_CR;
    else if (c == '\n')
      {
      ctx->flags &= ~PDKIM_SEEN_CR;
      if ((rc = pdkim_bodyline_complete(ctx)) != PDKIM_OK)
	return rc;
      }

    if (ctx->linebuf_offset == PDKIM_MAX_BODY_LINE_LEN-1)
      return PDKIM_ERR_LONG_LINE;
    }
  else
    {
    /* Processing header byte */
    if (c == '\r')
      ctx->flags |= PDKIM_SEEN_CR;
    else if (c == '\n')
      {
      if (!(ctx->flags & PDKIM_SEEN_CR))		/* emulate the CR */
	ctx->cur_header = string_catn(ctx->cur_header, &ctx->cur_header_size,
				&ctx->cur_header_len, CUS "\r", 1);

      if (ctx->flags & PDKIM_SEEN_LF)		/* Seen last header line */
	{
	if ((rc = pdkim_header_complete(ctx)) != PDKIM_OK)
	  return rc;

	ctx->flags = (ctx->flags & ~(PDKIM_SEEN_LF|PDKIM_SEEN_CR)) | PDKIM_PAST_HDRS;
	DEBUG(D_acl) debug_printf(
	    "PDKIM >> Body data for hash, canonicalized >>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	continue;
	}
      else
	ctx->flags = (ctx->flags & ~PDKIM_SEEN_CR) | PDKIM_SEEN_LF;
      }
    else if (ctx->flags & PDKIM_SEEN_LF)
      {
      if (!(c == '\t' || c == ' '))			/* End of header */
	if ((rc = pdkim_header_complete(ctx)) != PDKIM_OK)
	  return rc;
      ctx->flags &= ~PDKIM_SEEN_LF;
      }

    if (ctx->cur_header_len < PDKIM_MAX_HEADER_LEN)
      ctx->cur_header = string_catn(ctx->cur_header, &ctx->cur_header_size,
				  &ctx->cur_header_len, CUS &data[p], 1);
    }
  }
return PDKIM_OK;
}



/* Extend a grwong header with a continuation-linebreak */
static uschar *
pdkim_hdr_cont(uschar * str, int * size, int * ptr, int * col)
{
*col = 1;
return string_catn(str, size, ptr, US"\r\n\t", 3);
}



/*
 * RFC 5322 specifies that header line length SHOULD be no more than 78
 * lets make it so!
 *  pdkim_headcat
 *
 * returns uschar * (not nul-terminated)
 *
 * col: this int holds and receives column number (octets since last '\n')
 * str: partial string to append to
 * size: current buffer size for str
 * ptr: current tail-pointer for str
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

static uschar *
pdkim_headcat(int * col, uschar * str, int * size, int * ptr,
  const uschar * pad, const uschar * intro, const uschar * payload)
{
size_t l;

if (pad)
  {
  l = Ustrlen(pad);
  if (*col + l > 78)
    str = pdkim_hdr_cont(str, size, ptr, col);
  str = string_catn(str, size, ptr, pad, l);
  *col += l;
  }

l = (pad?1:0) + (intro?Ustrlen(intro):0);

if (*col + l > 78)
  { /*can't fit intro - start a new line to make room.*/
  str = pdkim_hdr_cont(str, size, ptr, col);
  l = intro?Ustrlen(intro):0;
  }

l += payload ? Ustrlen(payload):0 ;

while (l>77)
  { /* this fragment will not fit on a single line */
  if (pad)
    {
    str = string_catn(str, size, ptr, US" ", 1);
    *col += 1;
    pad = NULL; /* only want this once */
    l--;
    }

  if (intro)
    {
    size_t sl = Ustrlen(intro);

    str = string_catn(str, size, ptr, intro, sl);
    *col += sl;
    l -= sl;
    intro = NULL; /* only want this once */
    }

  if (payload)
    {
    size_t sl = Ustrlen(payload);
    size_t chomp = *col+sl < 77 ? sl : 78-*col;

    str = string_catn(str, size, ptr, payload, chomp);
    *col += chomp;
    payload += chomp;
    l -= chomp-1;
    }

  /* the while precondition tells us it didn't fit. */
  str = pdkim_hdr_cont(str, size, ptr, col);
  }

if (*col + l > 78)
  {
  str = pdkim_hdr_cont(str, size, ptr, col);
  pad = NULL;
  }

if (pad)
  {
  str = string_catn(str, size, ptr, US" ", 1);
  *col += 1;
  pad = NULL;
  }

if (intro)
  {
  size_t sl = Ustrlen(intro);

  str = string_catn(str, size, ptr, intro, sl);
  *col += sl;
  l -= sl;
  intro = NULL;
  }

if (payload)
  {
  size_t sl = Ustrlen(payload);

  str = string_catn(str, size, ptr, payload, sl);
  *col += sl;
  }

return str;
}


/* -------------------------------------------------------------------------- */

static uschar *
pdkim_create_header(pdkim_signature *sig, BOOL final)
{
uschar * base64_bh;
uschar * base64_b;
int col = 0;
uschar * hdr;       int hdr_size = 0, hdr_len = 0;
uschar * canon_all; int can_size = 0, can_len = 0;

canon_all = string_cat (NULL, &can_size, &can_len,
		      pdkim_canons[sig->canon_headers]);
canon_all = string_catn(canon_all, &can_size, &can_len, US"/", 1);
canon_all = string_cat (canon_all, &can_size, &can_len,
		      pdkim_canons[sig->canon_body]);
canon_all[can_len] = '\0';

hdr = string_cat(NULL, &hdr_size, &hdr_len,
		      US"DKIM-Signature: v="PDKIM_SIGNATURE_VERSION);
col = hdr_len;

/* Required and static bits */
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"a=",
		    dkim_sig_to_a_tag(sig));
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"q=",
		    pdkim_querymethods[sig->querymethod]);
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"c=",
		    canon_all);
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"d=",
		    sig->domain);
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"s=",
		    sig->selector);

/* list of header names can be split between items. */
  {
  uschar * n = string_copy(sig->headernames);
  uschar * i = US"h=";
  uschar * s = US";";

  while (*n)
    {
    uschar * c = Ustrchr(n, ':');

    if (c) *c ='\0';

    if (!i)
      hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, NULL, NULL, US":");

    hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, s, i, n);

    if (!c)
      break;

    n = c+1;
    s = NULL;
    i = NULL;
    }
  }

base64_bh = pdkim_encode_base64(&sig->bodyhash);
hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"bh=", base64_bh);

/* Optional bits */
if (sig->identity)
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"i=", sig->identity);

if (sig->created > 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->created);
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"t=", minibuf);
}

if (sig->expires > 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->expires);
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"x=", minibuf);
  }

if (sig->bodylength >= 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->bodylength);
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"l=", minibuf);
  }

/* Preliminary or final version? */
if (final)
  {
  base64_b = pdkim_encode_base64(&sig->sighash);
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"b=", base64_b);

  /* add trailing semicolon: I'm not sure if this is actually needed */
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, NULL, US";", US"");
  }
else
  {
  /* To satisfy the rule "all surrounding whitespace [...] deleted"
  ( RFC 6376 section 3.7 ) we ensure there is no whitespace here.  Otherwise
  the headcat routine could insert a linebreak which the relaxer would reduce
  to a single space preceding the terminating semicolon, resulting in an
  incorrect header-hash. */
  hdr = pdkim_headcat(&col, hdr, &hdr_size, &hdr_len, US";", US"b=;", US"");
  }

hdr[hdr_len] = '\0';
return hdr;
}


/* -------------------------------------------------------------------------- */

static pdkim_pubkey *
pdkim_key_from_dns(pdkim_ctx * ctx, pdkim_signature * sig, ev_ctx * vctx,
  const uschar ** errstr)
{
uschar * dns_txt_name, * dns_txt_reply;
pdkim_pubkey * p;

/* Fetch public key for signing domain, from DNS */

dns_txt_name = string_sprintf("%s._domainkey.%s.", sig->selector, sig->domain);

dns_txt_reply = store_get(PDKIM_DNS_TXT_MAX_RECLEN);
memset(dns_txt_reply, 0, PDKIM_DNS_TXT_MAX_RECLEN);

if (  ctx->dns_txt_callback(CS dns_txt_name, CS dns_txt_reply) != PDKIM_OK 
   || dns_txt_reply[0] == '\0'
   )
  {
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE;
  return NULL;
  }

DEBUG(D_acl)
  {
  debug_printf(
    "PDKIM >> Parsing public key record >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
    " Raw record: ");
  pdkim_quoteprint(CUS dns_txt_reply, Ustrlen(dns_txt_reply));
  }

if (  !(p = pdkim_parse_pubkey_record(ctx, CUS dns_txt_reply))
   || (Ustrcmp(p->srvtype, "*") != 0 && Ustrcmp(p->srvtype, "email") != 0)
   )
  {
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD;

  DEBUG(D_acl)
    {
    if (p)
      debug_printf(" Invalid public key service type '%s'\n", p->srvtype);
    else
      debug_printf(" Error while parsing public key record\n");
    debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }
  return NULL;
  }

DEBUG(D_acl) debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

/* Import public key */
if ((*errstr = exim_dkim_verify_init(&p->key, vctx)))
  {
  DEBUG(D_acl) debug_printf("verify_init: %s\n", *errstr);
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_IMPORT;
  return NULL;
  }

return p;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT int
pdkim_feed_finish(pdkim_ctx * ctx, pdkim_signature ** return_signatures,
  const uschar ** err)
{
pdkim_signature *sig = ctx->sig;

/* Check if we must still flush a (partial) header. If that is the
   case, the message has no body, and we must compute a body hash
   out of '<CR><LF>' */
if (ctx->cur_header && ctx->cur_header_len)
  {
  int rc = pdkim_header_complete(ctx);
  if (rc != PDKIM_OK) return rc;
  pdkim_update_bodyhash(ctx, "\r\n", 2);
  }
else
  DEBUG(D_acl) debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

/* Build (and/or evaluate) body hash */
pdkim_finish_bodyhash(ctx);

while (sig)
  {
  hctx hhash_ctx;
  uschar * sig_hdr = US"";
  blob hhash;
  blob hdata;
  int hdata_alloc = 0;

  hdata.data = NULL;
  hdata.len = 0;

  if (!exim_sha_init(&hhash_ctx, pdkim_hashes[sig->hashtype].exim_hashmethod))
    {
    DEBUG(D_acl)
      debug_printf("PDKIM: hash setup error, possibly nonhandled hashtype\n");
    break;
    }

  DEBUG(D_acl) debug_printf(
      "PDKIM >> Header data for hash, canonicalized, in sequence >>>>>>>>>>>>\n");

  /* SIGNING ---------------------------------------------------------------- */
  /* When signing, walk through our header list and add them to the hash. As we
     go, construct a list of the header's names to use for the h= parameter.
     Then append to that list any remaining header names for which there was no
     header to sign. */

  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    uschar * headernames = NULL;	/* Collected signed header names */
    int hs = 0, hl = 0;
    pdkim_stringlist *p;
    const uschar * l;
    uschar * s;
    int sep = 0;

    for (p = sig->headers; p; p = p->next)
      if (header_name_match(p->value, sig->sign_headers) == PDKIM_OK)
	{
	uschar * rh;
	/* Collect header names (Note: colon presence is guaranteed here) */
	uschar * q = Ustrchr(p->value, ':');

	headernames = string_catn(headernames, &hs, &hl,
			p->value, (q - US p->value) + (p->next ? 1 : 0));

	rh = sig->canon_headers == PDKIM_CANON_RELAXED
	  ? pdkim_relax_header(p->value, TRUE) /* cook header for relaxed canon */
	  : string_copy(CUS p->value);      /* just copy it for simple canon */

	/* Feed header to the hash algorithm */
	exim_sha_update(&hhash_ctx, CUS rh, Ustrlen(rh));

	/* Remember headers block for signing (when the library cannot do incremental)  */
	(void) exim_dkim_data_append(&hdata, &hdata_alloc, rh);

	DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
	}

    l = sig->sign_headers;
    while((s = string_nextinlist(&l, &sep, NULL, 0)))
      if (*s != '_')
	{			/*SSS string_append_listele() */
	if (hl > 0 && headernames[hl-1] != ':')
	  headernames = string_catn(headernames, &hs, &hl, US":", 1);

	headernames = string_cat(headernames, &hs, &hl, s);
	}
    headernames[hl] = '\0';

    /* Copy headernames to signature struct */
    sig->headernames = headernames;

    /* Create signature header with b= omitted */
    sig_hdr = pdkim_create_header(sig, FALSE);
    }

  /* VERIFICATION ----------------------------------------------------------- */
  /* When verifying, walk through the header name list in the h= parameter and
     add the headers to the hash in that order. */
  else
    {
    uschar * p = sig->headernames;
    uschar * q;
    pdkim_stringlist * hdrs;

    if (p)
      {
      /* clear tags */
      for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
	hdrs->tag = 0;

      p = string_copy(p);
      while(1)
	{
	if ((q = Ustrchr(p, ':')))
	  *q = '\0';

  /*XXX walk the list of headers in same order as received. */
	for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
	  if (  hdrs->tag == 0
	     && strncasecmp(CCS hdrs->value, CCS p, Ustrlen(p)) == 0
	     && (hdrs->value)[Ustrlen(p)] == ':'
	     )
	    {
	    /* cook header for relaxed canon, or just copy it for simple  */

	    uschar * rh = sig->canon_headers == PDKIM_CANON_RELAXED
	      ? pdkim_relax_header(hdrs->value, TRUE)
	      : string_copy(CUS hdrs->value);

	    /* Feed header to the hash algorithm */
	    exim_sha_update(&hhash_ctx, CUS rh, Ustrlen(rh));

	    DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
	    hdrs->tag = 1;
	    break;
	    }

	if (!q) break;
	p = q+1;
	}

      sig_hdr = string_copy(sig->rawsig_no_b_val);
      }
    }

  DEBUG(D_acl) debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

  /* Relax header if necessary */
  if (sig->canon_headers == PDKIM_CANON_RELAXED)
    sig_hdr = pdkim_relax_header(sig_hdr, FALSE);

  DEBUG(D_acl)
    {
    debug_printf(
	    "PDKIM >> Signed DKIM-Signature header, canonicalized >>>>>>>>>>>>>>>>>\n");
    pdkim_quoteprint(CUS sig_hdr, Ustrlen(sig_hdr));
    debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }

  /* Finalize header hash */
  exim_sha_update(&hhash_ctx, CUS sig_hdr, Ustrlen(sig_hdr));
  exim_sha_finish(&hhash_ctx, &hhash);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] Header hash computed: ", sig->domain);
    pdkim_hexprint(hhash.data, hhash.len);
    }

  /* Remember headers block for signing (when the library cannot do incremental)  */
/*XXX is this assuing algo == RSA? */
  if (ctx->flags & PDKIM_MODE_SIGN)
    (void) exim_dkim_data_append(&hdata, &hdata_alloc, US sig_hdr);

  /* SIGNING ---------------------------------------------------------------- */
  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    es_ctx sctx;

    /* Import private key, including the keytype */
/*XXX extend for non-RSA algos */
    if ((*err = exim_dkim_signing_init(US sig->privkey, &sctx)))
      {
      DEBUG(D_acl) debug_printf("signing_init: %s\n", *err);
      return PDKIM_ERR_RSA_PRIVKEY;
      }

    /* Do signing.  With OpenSSL we are signing the hash of headers just
    calculated, with GnuTLS we have to sign an entire block of headers
    (due to available interfaces) and it recalculates the hash internally. */

#if defined(SIGN_OPENSSL) || defined(SIGN_GCRYPT)
    hdata = hhash;
#endif

/*XXX extend for non-RSA algos */
    if ((*err = exim_dkim_sign(&sctx,
		  pdkim_hashes[sig->hashtype].exim_hashmethod,
		  &hdata, &sig->sighash)))
      {
      DEBUG(D_acl) debug_printf("signing: %s\n", *err);
      return PDKIM_ERR_RSA_SIGNING;
      }

    DEBUG(D_acl)
      {
      debug_printf( "PDKIM [%s] b computed: ", sig->domain);
      pdkim_hexprint(sig->sighash.data, sig->sighash.len);
      }

    sig->signature_header = pdkim_create_header(sig, TRUE);
    }

  /* VERIFICATION ----------------------------------------------------------- */
  else
    {
    ev_ctx vctx;

    /* Make sure we have all required signature tags */
    if (!(  sig->domain        && *sig->domain
	 && sig->selector      && *sig->selector
	 && sig->headernames   && *sig->headernames
	 && sig->bodyhash.data
	 && sig->sighash.data
	 && sig->keytype >= 0
	 && sig->hashtype >= 0
	 && sig->version
       ) )
      {
      sig->verify_status     = PDKIM_VERIFY_INVALID;
      sig->verify_ext_status = PDKIM_VERIFY_INVALID_SIGNATURE_ERROR;

      DEBUG(D_acl) debug_printf(
	  " Error in DKIM-Signature header: tags missing or invalid\n"
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      goto NEXT_VERIFY;
      }

    /* Make sure sig uses supported DKIM version (only v1) */
    if (sig->version != 1)
      {
      sig->verify_status     = PDKIM_VERIFY_INVALID;
      sig->verify_ext_status = PDKIM_VERIFY_INVALID_DKIM_VERSION;

      DEBUG(D_acl) debug_printf(
          " Error in DKIM-Signature header: unsupported DKIM version\n"
          "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      goto NEXT_VERIFY;
      }

    if (!(sig->pubkey = pdkim_key_from_dns(ctx, sig, &vctx, err)))
      goto NEXT_VERIFY;

    /* If the pubkey limits to a list of specific hashes, ignore sigs that
    do not have the hash part of the sig algorithm matching */

    if (sig->pubkey->hashes)
      {
      const uschar * list = sig->pubkey->hashes, * ele;
      int sep = ':';
      while ((ele = string_nextinlist(&list, &sep, NULL, 0)))
	if (Ustrcmp(ele, pdkim_hashes[sig->hashtype].dkim_hashname) == 0) break;
      if (!ele)
	{
	DEBUG(D_acl) debug_printf("pubkey h=%s vs. sig a=%s_%s\n",
	  sig->pubkey->hashes,
	  pdkim_keytypes[sig->keytype],
	  pdkim_hashes[sig->hashtype].dkim_hashname);
	sig->verify_status =      PDKIM_VERIFY_FAIL;
	sig->verify_ext_status =  PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH;
	goto NEXT_VERIFY;
	}
      }

    /* Check the signature */
/*XXX needs extension for non-RSA */
    if ((*err = exim_dkim_verify(&vctx,
		  pdkim_hashes[sig->hashtype].exim_hashmethod,
		  &hhash, &sig->sighash)))
      {
      DEBUG(D_acl) debug_printf("headers verify: %s\n", *err);
      sig->verify_status =      PDKIM_VERIFY_FAIL;
      sig->verify_ext_status =  PDKIM_VERIFY_FAIL_MESSAGE;
      goto NEXT_VERIFY;
      }


    /* We have a winner! (if bodyhash was correct earlier) */
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
pdkim_init_verify(int(*dns_txt_callback)(char *, char *), BOOL dot_stuffing)
{
pdkim_ctx * ctx;

ctx = store_get(sizeof(pdkim_ctx));
memset(ctx, 0, sizeof(pdkim_ctx));

if (dot_stuffing) ctx->flags = PDKIM_DOT_TERM;
ctx->linebuf = store_get(PDKIM_MAX_BODY_LINE_LEN);
ctx->dns_txt_callback = dns_txt_callback;

return ctx;
}


/* -------------------------------------------------------------------------- */

/*XXX ? needs extension to cover non-RSA algo?  */

DLLEXPORT pdkim_ctx *
pdkim_init_sign(uschar * domain, uschar * selector, uschar * privkey,
  uschar * hashname, BOOL dot_stuffed, int(*dns_txt_callback)(char *, char *),
  const uschar ** errstr)
{
int hashtype;
pdkim_ctx * ctx;
pdkim_signature * sig;

if (!domain || !selector || !privkey)
  return NULL;

ctx = store_get(sizeof(pdkim_ctx) + PDKIM_MAX_BODY_LINE_LEN + sizeof(pdkim_signature));
memset(ctx, 0, sizeof(pdkim_ctx));

ctx->flags = dot_stuffed ? PDKIM_MODE_SIGN | PDKIM_DOT_TERM : PDKIM_MODE_SIGN;
ctx->linebuf = CS (ctx+1);

DEBUG(D_acl) ctx->dns_txt_callback = dns_txt_callback;

sig = (pdkim_signature *)(ctx->linebuf + PDKIM_MAX_BODY_LINE_LEN);
memset(sig, 0, sizeof(pdkim_signature));

sig->bodylength = -1;
ctx->sig = sig;

sig->domain = string_copy(US domain);
sig->selector = string_copy(US selector);
sig->privkey = string_copy(US privkey);
/*XXX no keytype yet; comes from privkey */

for (hashtype = 0; hashtype < nelem(pdkim_hashes); hashtype++)
  if (Ustrcmp(hashname, pdkim_hashes[hashtype].dkim_hashname) == 0)
  { sig->hashtype = hashtype; break; }
if (hashtype >= nelem(pdkim_hashes))
  {
  DEBUG(D_acl)
    debug_printf("PDKIM: unrecognised hashname '%s'\n", hashname);
  return NULL;
  }

if (!exim_sha_init(&sig->body_hash_ctx, pdkim_hashes[hashtype].exim_hashmethod))
  {
  DEBUG(D_acl)
    debug_printf("PDKIM: hash setup error, possibly nonhandled hashtype\n");
  return NULL;
  }

DEBUG(D_acl)
  {
  pdkim_signature s = *sig;
  ev_ctx vctx;

  debug_printf("PDKIM (checking verify key)>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  if (!pdkim_key_from_dns(ctx, &s, &vctx, errstr))
    debug_printf("WARNING: bad dkim key in dns\n");
  debug_printf("PDKIM (finished checking verify key)<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }
return ctx;
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
pdkim_signature * sig = ctx->sig;

if (identity)
  sig->identity = string_copy(US identity);

sig->sign_headers = string_copy(sign_headers
	? US sign_headers : US PDKIM_DEFAULT_SIGN_HEADERS);

sig->canon_headers = canon_headers;
sig->canon_body = canon_body;
sig->bodylength = bodylength;
sig->created = created;
sig->expires = expires;

return PDKIM_OK;
}


void
pdkim_init(void)
{
exim_dkim_init();
}



#endif	/*DISABLE_DKIM*/
