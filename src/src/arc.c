/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
/* Experimental ARC support for Exim
   Copyright (c) The Exim Maintainers 2021 - 2024
   Copyright (c) Jeremy Harris 2018 - 2020
   License: GPL
   SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "exim.h"
#if defined EXPERIMENTAL_ARC
# if defined DISABLE_DKIM
#  error DKIM must also be enabled for ARC
# else

#  include "functions.h"
#  include "pdkim/pdkim.h"
#  include "pdkim/signing.h"

#  ifdef SUPPORT_DMARC
#   include "dmarc.h"
#  endif

extern pdkim_ctx * dkim_verify_ctx;
extern pdkim_ctx dkim_sign_ctx;

#define ARC_SIGN_OPT_TSTAMP	BIT(0)
#define ARC_SIGN_OPT_EXPIRE	BIT(1)

#define ARC_SIGN_DEFAULT_EXPIRE_DELTA (60 * 60 * 24 * 30)	/* one month */

/******************************************************************************/

typedef struct hdr_rlist {
  struct hdr_rlist *	prev;
  BOOL			used;
  header_line *		h;
} hdr_rlist;

typedef struct arc_line {
  header_line *	complete;	/* including the header name; nul-term */
  uschar *	relaxed;

  /* identified tag contents */
  /*XXX t= for AS? */
  blob		i;
  blob		cv;
  blob		a;
  blob		b;
  blob		bh;
  blob		d;
  blob		h;
  blob		s;
  blob		c;
  blob		l;
  blob		ip;

  /* tag content sub-portions */
  blob		a_algo;
  blob		a_hash;

  blob		c_head;
  blob		c_body;

  /* modified copy of b= field in line */
  blob		rawsig_no_b_val;
} arc_line;

typedef struct arc_set {
  struct arc_set *	next;
  struct arc_set *	prev;

  unsigned		instance;
  arc_line *		hdr_aar;
  arc_line *		hdr_ams;
  arc_line *		hdr_as;

  const uschar *	ams_verify_done;
  BOOL			ams_verify_passed;
} arc_set;

typedef struct arc_ctx {
  arc_set *	arcset_chain;
  arc_set *	arcset_chain_last;
} arc_ctx;

#define ARC_HDR_AAR	US"ARC-Authentication-Results:"
#define ARC_HDRLEN_AAR	27
#define ARC_HDR_AMS	US"ARC-Message-Signature:"
#define ARC_HDRLEN_AMS	22
#define ARC_HDR_AS	US"ARC-Seal:"
#define ARC_HDRLEN_AS	9
#define HDR_AR		US"Authentication-Results:"
#define HDRLEN_AR	23

typedef enum line_extract {
  le_instance_only,
  le_instance_plus_ip,
  le_all
} line_extract_t;

static time_t now;
static time_t expire;
static hdr_rlist * headers_rlist;
static arc_ctx arc_sign_ctx = { NULL };
static arc_ctx arc_verify_ctx = { NULL };

/* We build a context for either Sign or Verify.

For Verify, it's a fresh new one for ACL verify=arc - there is no connection
with the single line handling done during reception via the DKIM feed.

For Verify we do it twice; initially during reception (via the DKIM feed)
and then later for the full verification.

The former only looks at AMS headers, to discover what hash(es) we need done for
ARC on the message body; we call back to the DKIM code to set up so that it does
them for us during reception.  That call needs info from many of the AMS tags;
arc_parse_line() for only the AMS is called asking for all the tag types.
That context is then discarded.

Later, for Verify, we look at ARC headers again and then grab the hash result
from the DKIM layer.  arc_parse_line() is called for all 3 line types,
gathering info for only 'i' and 'ip' tags from AAR headers,
for all tag types from AMS and AS headers.


For Sign, while running through the existing headers (before adding any for
this signing operation, we "take copies" of the headers, we call
arc_parse_line() gathering only the 'i' tag (instance) information.
*/


/******************************************************************************/


/* Get the instance number from the header.
Return 0 on error */
static unsigned
arc_instance_from_hdr(const arc_line * al)
{
const uschar * s = al->i.data;
if (!s || !al->i.len) return 0;
return (unsigned) atoi(CCS s);
}


static uschar *
skip_fws(uschar * s)
{
uschar c = *s;
while (c && (c == ' ' || c == '\t' || c == '\n' || c == '\r')) c = *++s;
return s;
}


/* Locate instance struct on chain, inserting a new one if
needed.  The chain is in increasing-instance-number order
by the "next" link, and we have a "prev" link also.
*/

static arc_set *
arc_find_set(arc_ctx * ctx, unsigned i)
{
arc_set ** pas, * as, * next, * prev;

for (pas = &ctx->arcset_chain, prev = NULL, next = ctx->arcset_chain;
     as = *pas; pas = &as->next)
  {
  if (as->instance > i) break;
  if (as->instance == i)
    {
    DEBUG(D_acl) debug_printf("ARC: existing instance %u\n", i);
    return as;
    }
  next = as->next;
  prev = as;
  }

DEBUG(D_acl) debug_printf("ARC: new instance %u\n", i);
*pas = as = store_get(sizeof(arc_set), GET_UNTAINTED);
memset(as, 0, sizeof(arc_set));
as->next = next;
as->prev = prev;
as->instance = i;
if (next)
  next->prev = as;
else
  ctx->arcset_chain_last = as;
return as;
}



/* Insert a tag content into the line structure.
Note this is a reference to existing data, not a copy.
Check for already-seen tag.
The string-pointer is on the '=' for entry.  Update it past the
content (to the ;) on return;
*/

static uschar *
arc_insert_tagvalue(arc_line * al, unsigned loff, uschar ** ss)
{
uschar * s = *ss;
uschar c = *++s;
blob * b = (blob *)(US al + loff);
size_t len = 0;

/* [FWS] tag-value [FWS] */

if (b->data) return US"fail";
s = skip_fws(s);						/* FWS */

b->data = s;
while ((c = *s) && c != ';') { len++; s++; }
*ss = s;
while (len && ((c = s[-1]) == ' ' || c == '\t' || c == '\n' || c == '\r'))
  { s--; len--; }						/* FWS */
b->len = len;
return NULL;
}


/* Inspect a header line, noting known tag fields.
Check for duplicate named tags.

See the file block comment for how this is used.

Return: NULL for good, or an error string
*/

static uschar *
arc_parse_line(arc_line * al, header_line * h, unsigned off, line_extract_t l_ext)
{
uschar * s = h->text + off;
uschar * r = NULL;
uschar c;

al->complete = h;

if (l_ext == le_all)		/* need to grab rawsig_no_b */
  {
  al->rawsig_no_b_val.data = store_get(h->slen + 1, GET_TAINTED);
  memcpy(al->rawsig_no_b_val.data, h->text, off);	/* copy the header name blind */
  r = al->rawsig_no_b_val.data + off;
  al->rawsig_no_b_val.len = off;
  }

/* tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ] */

while ((c = *s))
  {
  char tagchar;
  uschar * t;
  unsigned i = 0;
  uschar * fieldstart = s;
  uschar * bstart = NULL, * bend;

  /* tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS] */
  /*X or just a naked FQDN, in a AAR ! */

  s = skip_fws(s);						/* leading FWS */
  if (!*s) break;
  tagchar = *s++;
  if (!*(s = skip_fws(s))) break;				/* FWS */

  switch (tagchar)
    {
    case 'a':				/* a= AMS algorithm */
      if (l_ext == le_all && *s == '=')
	{
	if (arc_insert_tagvalue(al, offsetof(arc_line, a), &s)) return US"a tag dup";

	/* substructure: algo-hash   (eg. rsa-sha256) */

	t = al->a_algo.data = al->a.data;
	while (*t != '-')
	  if (!*t++ || ++i > al->a.len) return US"no '-' in 'a' value";
	al->a_algo.len = i;
	if (*t++ != '-') return US"no '-' in 'a' value";
	al->a_hash.data = t;
	al->a_hash.len = al->a.len - i - 1;
	}
      break;
    case 'b':
      if (l_ext == le_all)
	{
	gstring * g = NULL;

	switch (*s)
	  {
	  case '=':			/* b= AMS signature */
	    if (al->b.data) return US"already b data";
	    bstart = s+1;

	    /* The signature can have FWS inserted in the content;
	    make a stripped copy */

	    while ((c = *++s) && c != ';')
	      if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
		g = string_catn(g, s, 1);
	    if (!g) return US"no b= value";
	    al->b.len = len_string_from_gstring(g, &al->b.data);
	    gstring_release_unused(g);
	    bend = s;
	    break;
	  case 'h':			/* bh= AMS body hash */
	    s = skip_fws(++s);					/* FWS */
	    if (*s == '=')
	      {
	      if (al->bh.data) return US"already bh data";

	      /* The bodyhash can have FWS inserted in the content;
	      make a stripped copy */

	      while ((c = *++s) && c != ';')
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
		  g = string_catn(g, s, 1);
	      if (!g) return US"no bh= value";
	      al->bh.len = len_string_from_gstring(g, &al->bh.data);
	      gstring_release_unused(g);
	      }
	    break;
	  default:
	    return US"b? tag";
	  }
	}
      break;
    case 'c':
      if (l_ext == le_all) switch (*s)
	{
	case '=':			/* c= AMS canonicalisation */
	  if (arc_insert_tagvalue(al, offsetof(arc_line, c), &s)) return US"c tag dup";

	  /* substructure: head/body   (eg. relaxed/simple)) */

	  t = al->c_head.data = al->c.data;
	  while (isalpha(*t))
	    if (!*t++ || ++i > al->a.len) break;
	  al->c_head.len = i;
	  if (*t++ == '/')		/* /body is optional */
	    {
	    al->c_body.data = t;
	    al->c_body.len = al->c.len - i - 1;
	    }
	  else
	    {
	    al->c_body.data = US"simple";
	    al->c_body.len = 6;
	    }
	  break;
	case 'v':			/* cv= AS validity */
	  s = skip_fws(s);
	  if (*++s == '=')
	    if (arc_insert_tagvalue(al, offsetof(arc_line, cv), &s))
	      return US"cv tag dup";
	  break;
	}
      break;
    case 'd':				/* d= AMS domain */
      if (l_ext == le_all && *s == '=')
	if (arc_insert_tagvalue(al, offsetof(arc_line, d), &s))
	  return US"d tag dup";
      break;
    case 'h':				/* h= AMS headers */
      if (*s == '=')
	if (arc_insert_tagvalue(al, offsetof(arc_line, h), &s))
	  return US"h tag dup";
      break;
    case 'i':				/* i= ARC set instance */
      if (*s == '=')
	{
	if (arc_insert_tagvalue(al, offsetof(arc_line, i), &s))
	  return US"i tag dup";
	if (l_ext == le_instance_only)
	  goto done;			/* early-out */
	}
      break;
    case 'l':				/* l= bodylength */
      if (l_ext == le_all && *s == '=')
	if (arc_insert_tagvalue(al, offsetof(arc_line, l), &s))
	  return US"l tag dup";
      break;
    case 's':
      if (*s == '=' && l_ext == le_all)
	{
	if (arc_insert_tagvalue(al, offsetof(arc_line, s), &s))
	  return US"s tag dup";
	}
      else if (  l_ext == le_instance_plus_ip
	      && Ustrncmp(s, "mtp.remote-ip", 13) == 0)
	{			/* smtp.remote-ip= AAR reception data */
	s += 13;
	s = skip_fws(s);
	if (*s != '=') return US"smtp.remote_ip tag val";
	if (arc_insert_tagvalue(al, offsetof(arc_line, ip), &s))
	  return US"ip tag dup";
	}
      break;
    }

  while ((c = *s) && c != ';') s++;	/* end of this tag=value */
  if (c) s++;				/* ; after tag-spec */

  /* for all but the b= tag, copy the field including FWS.  For the b=,
  drop the tag content. */

  if (r)
    if (bstart)
      {
      size_t n = bstart - fieldstart;
      memcpy(r, fieldstart, n);		/* FWS "b=" */
      r += n;
      al->rawsig_no_b_val.len += n;
      n = s - bend;
      memcpy(r, bend, n);		/* FWS ";" */
      r += n;
      al->rawsig_no_b_val.len += n;
      }
    else
      {
      size_t n = s - fieldstart;
      memcpy(r, fieldstart, n);
      r += n;
      al->rawsig_no_b_val.len += n;
      }
  }

if (r)
  *r = '\0';

done:
/* debug_printf("%s: finshed\n", __FUNCTION__); */
return NULL;
}


/* Insert one header line in the correct set of the chain,
adding instances as needed and checking for duplicate lines.
*/

static uschar *
arc_insert_hdr(arc_ctx * ctx, header_line * h, unsigned off, unsigned hoff,
  line_extract_t l_ext, arc_line ** alp_ret)
{
unsigned i;
arc_set * as;
arc_line * al = store_get(sizeof(arc_line), GET_UNTAINTED), ** alp;
uschar * e;

memset(al, 0, sizeof(arc_line));

if ((e = arc_parse_line(al, h, off, l_ext)))
  {
  DEBUG(D_acl) if (e) debug_printf("ARC: %s\n", e);
  return string_sprintf("line parse: %s", e);
  }
if (!(i = arc_instance_from_hdr(al)))	return US"instance find";
if (i > 50)				return US"overlarge instance number";
if (!(as = arc_find_set(ctx, i)))	return US"set find";
if (*(alp = (arc_line **)(US as + hoff))) return US"dup hdr";

*alp = al;
if (alp_ret) *alp_ret = al;
return NULL;
}



/* Called for both Sign and Verify */

static const uschar *
arc_try_header(arc_ctx * ctx, header_line * h, BOOL is_signing)
{
const uschar * e;

/*debug_printf("consider hdr '%s'\n", h->text);*/
if (strncmpic(ARC_HDR_AAR, h->text, ARC_HDRLEN_AAR) == 0)
  {
  DEBUG(D_acl)
    {
    int len = h->slen;
    uschar * s;
    for (s = h->text + h->slen; s[-1] == '\r' || s[-1] == '\n'; )
      s--, len--;
    debug_printf("ARC: found AAR: %.*s\n", len, h->text);
    }
  if ((e = arc_insert_hdr(ctx, h, ARC_HDRLEN_AAR, offsetof(arc_set, hdr_aar),
	      is_signing ? le_instance_only : le_instance_plus_ip, NULL)))
    {
    DEBUG(D_acl) debug_printf("inserting AAR: %s\n", e);
    return string_sprintf("inserting AAR: %s", e);
    }
  }
else if (strncmpic(ARC_HDR_AMS, h->text, ARC_HDRLEN_AMS) == 0)
  {
  arc_line * ams;

  DEBUG(D_acl)
    {
    int len = h->slen;
    uschar * s;
    for (s = h->text + h->slen; s[-1] == '\r' || s[-1] == '\n'; )
      s--, len--;
    debug_printf("ARC: found AMS: %.*s\n", len, h->text);
    }
  if ((e = arc_insert_hdr(ctx, h, ARC_HDRLEN_AMS, offsetof(arc_set, hdr_ams),
	      is_signing ? le_instance_only : le_all, &ams)))
    {
    DEBUG(D_acl) debug_printf("inserting AMS: %s\n", e);
    return string_sprintf("inserting AMS: %s", e);
    }

  /* defaults */
  if (!ams->c.data)
    {
    ams->c_head.data = US"simple"; ams->c_head.len = 6;
    ams->c_body = ams->c_head;
    }
  }
else if (strncmpic(ARC_HDR_AS, h->text, ARC_HDRLEN_AS) == 0)
  {
  DEBUG(D_acl)
    {
    int len = h->slen;
    uschar * s;
    for (s = h->text + h->slen; s[-1] == '\r' || s[-1] == '\n'; )
      s--, len--;
    debug_printf("ARC: found AS: %.*s\n", len, h->text);
    }
  if ((e = arc_insert_hdr(ctx, h, ARC_HDRLEN_AS, offsetof(arc_set, hdr_as),
	    is_signing ? le_instance_only : le_all, NULL)))
    {
    DEBUG(D_acl) debug_printf("inserting AS: %s\n", e);
    return string_sprintf("inserting AS: %s", e);
    }
  }
return NULL;
}



/* Gather the chain of arc sets from the headers.
Check for duplicates while that is done.  Also build the
reverse-order headers list.
Called on an ACL verify=arc condition.

Return: ARC state if determined, eg. by lack of any ARC chain.
*/

static const uschar *
arc_vfy_collect_hdrs(arc_ctx * ctx)
{
header_line * h;
hdr_rlist * r = NULL, * rprev = NULL;
const uschar * e;

DEBUG(D_acl) debug_printf("ARC: collecting arc sets\n");
for (h = header_list; h; h = h->next)
  {
  r = store_get(sizeof(hdr_rlist), GET_UNTAINTED);
  r->prev = rprev;
  r->used = FALSE;
  r->h = h;
  rprev = r;

  if ((e = arc_try_header(ctx, h, FALSE)))
    {
    arc_state_reason = string_sprintf("collecting headers: %s", e);
    return US"fail";
    }
  }
headers_rlist = r;

if (!ctx->arcset_chain) return US"none";
return NULL;
}


static BOOL
arc_cv_match(arc_line * al, const uschar * s)
{
return Ustrncmp(s, al->cv.data, al->cv.len) == 0;
}

/******************************************************************************/

/* Return the hash of headers from the message that the AMS claims it
signed.
*/

static void
arc_get_verify_hhash(arc_ctx * ctx, arc_line * ams, blob * hhash)
{
const uschar * headernames = string_copyn(ams->h.data, ams->h.len);
const uschar * hn;
int sep = ':';
hdr_rlist * r;
BOOL relaxed = Ustrncmp(US"relaxed", ams->c_head.data, ams->c_head.len) == 0;
int hashtype = pdkim_hashname_to_hashtype(
		    ams->a_hash.data, ams->a_hash.len);
hctx hhash_ctx;
const uschar * s;
int len;

if (  hashtype == -1
   || !exim_sha_init(&hhash_ctx, pdkim_hashes[hashtype].exim_hashmethod))
  {
  DEBUG(D_acl)
      debug_printf("ARC: hash setup error, possibly nonhandled hashtype\n");
  return;
  }

/* For each headername in the list from the AMS (walking in order)
walk the message headers in reverse order, adding to the hash any
found for the first time. For that last point, maintain used-marks
on the list of message headers. */

DEBUG(D_acl) debug_printf("ARC: AMS header data for verification:\n");

for (r = headers_rlist; r; r = r->prev)
  r->used = FALSE;
while ((hn = string_nextinlist(&headernames, &sep, NULL, 0)))
  for (r = headers_rlist; r; r = r->prev)
    if (  !r->used
       && strncasecmp(CCS (s = r->h->text), CCS hn, Ustrlen(hn)) == 0
       )
      {
      if (relaxed) s = pdkim_relax_header_n(s, r->h->slen, TRUE);

      len = Ustrlen(s);
      DEBUG(D_acl) pdkim_quoteprint(s, len);
      exim_sha_update_string(&hhash_ctx, s);
      r->used = TRUE;
      break;
      }

/* Finally add in the signature header (with the b= tag stripped); no CRLF */

s = ams->rawsig_no_b_val.data, len = ams->rawsig_no_b_val.len;
if (relaxed)
  len = Ustrlen(s = pdkim_relax_header_n(s, len, FALSE));
DEBUG(D_acl) pdkim_quoteprint(s, len);
exim_sha_update(&hhash_ctx, s, len);

exim_sha_finish(&hhash_ctx, hhash);
DEBUG(D_acl)
  { debug_printf("ARC: header hash: "); pdkim_hexprint(hhash->data, hhash->len); }
return;
}




static pdkim_pubkey *
arc_line_to_pubkey(arc_line * al)
{
uschar * dns_txt;
pdkim_pubkey * p;

if (!(dns_txt = dkim_exim_query_dns_txt(string_sprintf("%.*s._domainkey.%.*s",
	  (int)al->s.len, al->s.data, (int)al->d.len, al->d.data))))
  {
  DEBUG(D_acl) debug_printf("pubkey dns lookup fail\n");
  return NULL;
  }

if (  !(p = pdkim_parse_pubkey_record(dns_txt))
   || (Ustrcmp(p->srvtype, "*") != 0 && Ustrcmp(p->srvtype, "email") != 0)
   )
  {
  DEBUG(D_acl) debug_printf("pubkey dns lookup format error\n");
  return NULL;
  }

/* If the pubkey limits use to specified hashes, reject unusable
signatures. XXX should we have looked for multiple dns records? */

if (p->hashes)
  {
  const uschar * list = p->hashes, * ele;
  int sep = ':';

  while ((ele = string_nextinlist(&list, &sep, NULL, 0)))
    if (Ustrncmp(ele, al->a_hash.data, al->a_hash.len) == 0) break;
  if (!ele)
    {
    DEBUG(D_acl) debug_printf("pubkey h=%s vs sig a=%.*s\n",
			      p->hashes, (int)al->a.len, al->a.data);
    return NULL;
    }
  }
return p;
}




static pdkim_bodyhash *
arc_ams_setup_vfy_bodyhash(arc_line * ams)
{
int canon_head = -1, canon_body = -1;
long bodylen;

if (!ams->c.data) ams->c.data = US"simple";	/* RFC 6376 (DKIM) default */
pdkim_cstring_to_canons(ams->c.data, ams->c.len, &canon_head, &canon_body);
bodylen = ams->l.data
	? strtol(CS string_copyn(ams->l.data, ams->l.len), NULL, 10) : -1;

return pdkim_set_bodyhash(dkim_verify_ctx,
	pdkim_hashname_to_hashtype(ams->a_hash.data, ams->a_hash.len),
	canon_body,
	bodylen);
}



/* Verify an AMS. This is a DKIM-sig header, but with an ARC i= tag
and without a DKIM v= tag.
*/

static const uschar *
arc_ams_verify(arc_ctx * ctx, arc_set * as)
{
arc_line * ams = as->hdr_ams;
pdkim_bodyhash * b;
pdkim_pubkey * p;
blob sighash;
blob hhash;
ev_ctx vctx;
int hashtype;
const uschar * errstr;

as->ams_verify_done = US"in-progress";

/* Check the AMS has all the required tags:
   "a="  algorithm
   "b="  signature
   "bh=" body hash
   "d="  domain (for key lookup)
   "h="  headers (included in signature)
   "s="  key-selector (for key lookup)
*/
if (  !ams->a.data || !ams->b.data || !ams->bh.data || !ams->d.data
   || !ams->h.data || !ams->s.data)
  {
  as->ams_verify_done = arc_state_reason = US"required tag missing";
  return US"fail";
  }


/* The bodyhash should have been created earlier, and the dkim code should
have managed calculating it during message input.  Find the reference to it. */

if (!(b = arc_ams_setup_vfy_bodyhash(ams)))
  {
  as->ams_verify_done = arc_state_reason = US"internal hash setup error";
  return US"fail";
  }

DEBUG(D_acl)
  {
  debug_printf("ARC i=%d AMS   Body bytes hashed: %lu\n"
	       "              Body %.*s computed: ",
	       as->instance, b->signed_body_bytes,
	       (int)ams->a_hash.len, ams->a_hash.data);
  pdkim_hexprint(CUS b->bh.data, b->bh.len);
  }

/* We know the bh-tag blob is of a nul-term string, so safe as a string */

if (  !ams->bh.data
   || (pdkim_decode_base64(ams->bh.data, &sighash), sighash.len != b->bh.len)
   || memcmp(sighash.data, b->bh.data, b->bh.len) != 0
   )
  {
  DEBUG(D_acl)
    {
    debug_printf("ARC i=%d AMS Body hash from headers: ", as->instance);
    pdkim_hexprint(sighash.data, sighash.len);
    debug_printf("ARC i=%d AMS Body hash did NOT match\n", as->instance);
    }
  return as->ams_verify_done = arc_state_reason = US"AMS body hash miscompare";
  }

DEBUG(D_acl) debug_printf("ARC i=%d AMS Body hash compared OK\n", as->instance);

/* Get the public key from DNS */

if (!(p = arc_line_to_pubkey(ams)))
  return as->ams_verify_done = arc_state_reason = US"pubkey problem";

/* We know the b-tag blob is of a nul-term string, so safe as a string */
pdkim_decode_base64(ams->b.data, &sighash);

arc_get_verify_hhash(ctx, ams, &hhash);

/* Setup the interface to the signing library */

if ((errstr = exim_dkim_verify_init(&p->key, KEYFMT_DER, &vctx, NULL)))
  {
  DEBUG(D_acl) debug_printf("ARC verify init: %s\n", errstr);
  as->ams_verify_done = arc_state_reason = US"internal sigverify init error";
  return US"fail";
  }

hashtype = pdkim_hashname_to_hashtype(ams->a_hash.data, ams->a_hash.len);
if (hashtype == -1)
  {
  DEBUG(D_acl) debug_printf("ARC i=%d AMS verify bad a_hash\n", as->instance);
  return as->ams_verify_done = arc_state_reason = US"AMS sig nonverify";
  }

if ((errstr = exim_dkim_verify(&vctx,
	  pdkim_hashes[hashtype].exim_hashmethod, &hhash, &sighash)))
  {
  DEBUG(D_acl) debug_printf("ARC i=%d AMS verify %s\n", as->instance, errstr);
  return as->ams_verify_done = arc_state_reason = US"AMS sig nonverify";
  }

DEBUG(D_acl) debug_printf("ARC i=%d AMS verify pass\n", as->instance);
as->ams_verify_passed = TRUE;
return NULL;
}



/* Check the sets are instance-continuous and that all
members are present.  Check that no arc_seals are "fail".
Set the highest instance number global.
Verify the latest AMS.
*/
static uschar *
arc_headers_check(arc_ctx * ctx)
{
arc_set * as;
int inst;
BOOL ams_fail_found = FALSE;

if (!(as = ctx->arcset_chain_last))
  return US"none";

for(inst = as->instance; as; as = as->prev, inst--)
  {
  if (as->instance != inst)
    arc_state_reason = string_sprintf("i=%d (sequence; expected %d)",
      as->instance, inst);
  else if (!as->hdr_aar || !as->hdr_ams || !as->hdr_as)
    arc_state_reason = string_sprintf("i=%d (missing header)", as->instance);
  else if (arc_cv_match(as->hdr_as, US"fail"))
    arc_state_reason = string_sprintf("i=%d (cv)", as->instance);
  else
    goto good;

  DEBUG(D_acl) debug_printf("ARC chain fail at %s\n", arc_state_reason);
  return US"fail";

  good:
  /* Evaluate the oldest-pass AMS validation while we're here.
  It does not affect the AS chain validation but is reported as
  auxilary info. */

  if (!ams_fail_found)
    if (arc_ams_verify(ctx, as))
      ams_fail_found = TRUE;
    else
      arc_oldest_pass = inst;
  arc_state_reason = NULL;
  }
if (inst != 0)
  {
  arc_state_reason = string_sprintf("(sequence; expected i=%d)", inst);
  DEBUG(D_acl) debug_printf("ARC chain fail %s\n", arc_state_reason);
  return US"fail";
  }

arc_received = ctx->arcset_chain_last;
arc_received_instance = arc_received->instance;

/* We can skip the latest-AMS validation, if we already did it. */

as = ctx->arcset_chain_last;
if (!as->ams_verify_passed)
  {
  if (as->ams_verify_done)
    {
    arc_state_reason = as->ams_verify_done;
    return US"fail";
    }
  if (!!arc_ams_verify(ctx, as))
    return US"fail";
  }
return NULL;
}


/******************************************************************************/
static const uschar *
arc_seal_verify(arc_ctx * ctx, arc_set * as)
{
arc_line * hdr_as = as->hdr_as;
arc_set * as2;
int hashtype;
hctx hhash_ctx;
blob hhash_computed;
blob sighash;
ev_ctx vctx;
pdkim_pubkey * p;
const uschar * errstr;

DEBUG(D_acl) debug_printf("ARC: AS vfy i=%d\n", as->instance);
/*
       1.  If the value of the "cv" tag on that seal is "fail", the
           chain state is "fail" and the algorithm stops here.  (This
           step SHOULD be skipped if the earlier step (2.1) was
           performed) [it was]

       2.  In Boolean nomenclature: if ((i == 1 && cv != "none") or (cv
           == "none" && i != 1)) then the chain state is "fail" and the
           algorithm stops here (note that the ordering of the logic is
           structured for short-circuit evaluation).
*/

if (  as->instance == 1 && !arc_cv_match(hdr_as, US"none")
   || arc_cv_match(hdr_as, US"none") && as->instance != 1
   )
  {
  arc_state_reason = US"seal cv state";
  return US"fail";
  }

/*
       3.  Initialize a hash function corresponding to the "a" tag of
           the ARC-Seal.
*/

hashtype = pdkim_hashname_to_hashtype(hdr_as->a_hash.data, hdr_as->a_hash.len);

if (  hashtype == -1
   || !exim_sha_init(&hhash_ctx, pdkim_hashes[hashtype].exim_hashmethod))
  {
  DEBUG(D_acl)
      debug_printf("ARC: hash setup error, possibly nonhandled hashtype\n");
  arc_state_reason = US"seal hash setup error";
  return US"fail";
  }

/*
       4.  Compute the canonicalized form of the ARC header fields, in
           the order described in Section 5.4.2, using the "relaxed"
           header canonicalization defined in Section 3.4.2 of
           [RFC6376].  Pass the canonicalized result to the hash
           function.

Headers are CRLF-separated, but the last one is not crlf-terminated.
*/

DEBUG(D_acl) debug_printf("ARC: AS header data for verification:\n");
for (as2 = ctx->arcset_chain;
     as2 && as2->instance <= as->instance;
     as2 = as2->next)
  {
  arc_line * al;
  uschar * s;
  int len;

  al = as2->hdr_aar;
  if (!(s = al->relaxed))
    al->relaxed = s = pdkim_relax_header_n(al->complete->text,
					    al->complete->slen, TRUE);
  len = Ustrlen(s);
  DEBUG(D_acl) pdkim_quoteprint(s, len);
  exim_sha_update(&hhash_ctx, s, len);

  al = as2->hdr_ams;
  if (!(s = al->relaxed))
    al->relaxed = s = pdkim_relax_header_n(al->complete->text,
					    al->complete->slen, TRUE);
  len = Ustrlen(s);
  DEBUG(D_acl) pdkim_quoteprint(s, len);
  exim_sha_update(&hhash_ctx, s, len);

  al = as2->hdr_as;
  if (as2->instance == as->instance)
    s = pdkim_relax_header_n(al->rawsig_no_b_val.data,
					al->rawsig_no_b_val.len, FALSE);
  else if (!(s = al->relaxed))
    al->relaxed = s = pdkim_relax_header_n(al->complete->text,
					    al->complete->slen, TRUE);
  len = Ustrlen(s);
  DEBUG(D_acl) pdkim_quoteprint(s, len);
  exim_sha_update(&hhash_ctx, s, len);
  }

/*
       5.  Retrieve the final digest from the hash function.
*/

exim_sha_finish(&hhash_ctx, &hhash_computed);
DEBUG(D_acl)
  {
  debug_printf("ARC i=%d AS Header %.*s computed: ",
    as->instance, (int)hdr_as->a_hash.len, hdr_as->a_hash.data);
  pdkim_hexprint(hhash_computed.data, hhash_computed.len);
  }


/*
       6.  Retrieve the public key identified by the "s" and "d" tags in
           the ARC-Seal, as described in Section 4.1.6.
*/

if (!(p = arc_line_to_pubkey(hdr_as)))
  return US"pubkey problem";

/*
       7.  Determine whether the signature portion ("b" tag) of the ARC-
           Seal and the digest computed above are valid according to the
           public key.  (See also Section Section 8.4 for failure case
           handling)

       8.  If the signature is not valid, the chain state is "fail" and
           the algorithm stops here.
*/

/* We know the b-tag blob is of a nul-term string, so safe as a string */
pdkim_decode_base64(hdr_as->b.data, &sighash);

if ((errstr = exim_dkim_verify_init(&p->key, KEYFMT_DER, &vctx, NULL)))
  {
  DEBUG(D_acl) debug_printf("ARC verify init: %s\n", errstr);
  return US"fail";
  }

if ((errstr = exim_dkim_verify(&vctx,
	      pdkim_hashes[hashtype].exim_hashmethod,
	      &hhash_computed, &sighash)))
  {
  DEBUG(D_acl)
    debug_printf("ARC i=%d AS headers verify: %s\n", as->instance, errstr);
  arc_state_reason = US"seal sigverify error";
  return US"fail";
  }

DEBUG(D_acl) debug_printf("ARC: AS vfy i=%d pass\n", as->instance);
return NULL;
}


static const uschar *
arc_verify_seals(arc_ctx * ctx)
{
arc_set * as = ctx->arcset_chain_last;

if (!as)
  return US"none";

for ( ; as; as = as->prev) if (arc_seal_verify(ctx, as)) return US"fail";

DEBUG(D_acl) debug_printf("ARC: AS vfy overall pass\n");
return NULL;
}
/******************************************************************************/

/* Do ARC verification.  Called from DATA ACL, on a verify = arc
condition.  No arguments; we are checking globals.

Return:  The ARC state, or NULL on error.
*/

const uschar *
acl_verify_arc(void)
{
const uschar * res;

memset(&arc_verify_ctx, 0, sizeof(arc_verify_ctx));

if (!dkim_verify_ctx)
  {
  DEBUG(D_acl) debug_printf("ARC: no DKIM verify context\n");
  return NULL;
  }

/* AS evaluation, per
https://tools.ietf.org/html/draft-ietf-dmarc-arc-protocol-10#section-6
*/
/* 1.  Collect all ARC sets currently on the message.  If there were
       none, the ARC state is "none" and the algorithm stops here.
*/

if ((res = arc_vfy_collect_hdrs(&arc_verify_ctx)))
  goto out;

/* 2.  If the form of any ARC set is invalid (e.g., does not contain
       exactly one of each of the three ARC-specific header fields),
       then the chain state is "fail" and the algorithm stops here.

       1.  To avoid the overhead of unnecessary computation and delay
           from crypto and DNS operations, the cv value for all ARC-
           Seal(s) MAY be checked at this point.  If any of the values
           are "fail", then the overall state of the chain is "fail" and
           the algorithm stops here.

   3.  Conduct verification of the ARC-Message-Signature header field
       bearing the highest instance number.  If this verification fails,
       then the chain state is "fail" and the algorithm stops here.
*/

if ((res = arc_headers_check(&arc_verify_ctx)))
  goto out;

/* 4.  For each ARC-Seal from the "N"th instance to the first, apply the
       following logic:

       1.  If the value of the "cv" tag on that seal is "fail", the
           chain state is "fail" and the algorithm stops here.  (This
           step SHOULD be skipped if the earlier step (2.1) was
           performed)

       2.  In Boolean nomenclature: if ((i == 1 && cv != "none") or (cv
           == "none" && i != 1)) then the chain state is "fail" and the
           algorithm stops here (note that the ordering of the logic is
           structured for short-circuit evaluation).

       3.  Initialize a hash function corresponding to the "a" tag of
           the ARC-Seal.

       4.  Compute the canonicalized form of the ARC header fields, in
           the order described in Section 5.4.2, using the "relaxed"
           header canonicalization defined in Section 3.4.2 of
           [RFC6376].  Pass the canonicalized result to the hash
           function.

       5.  Retrieve the final digest from the hash function.

       6.  Retrieve the public key identified by the "s" and "d" tags in
           the ARC-Seal, as described in Section 4.1.6.

       7.  Determine whether the signature portion ("b" tag) of the ARC-
           Seal and the digest computed above are valid according to the
           public key.  (See also Section Section 8.4 for failure case
           handling)

       8.  If the signature is not valid, the chain state is "fail" and
           the algorithm stops here.

   5.  If all seals pass validation, then the chain state is "pass", and
       the algorithm is complete.
*/

if ((res = arc_verify_seals(&arc_verify_ctx)))
  goto out;

res = US"pass";

out:
  return res;
}

/******************************************************************************/

/* Prepend the header to the rlist */

static hdr_rlist *
arc_rlist_entry(hdr_rlist * list, const uschar * s, int len)
{
hdr_rlist * r = store_get(sizeof(hdr_rlist) + sizeof(header_line), GET_UNTAINTED);
header_line * h = r->h = (header_line *)(r+1);

r->prev = list;
r->used = FALSE;
h->next = NULL;
h->type = 0;
h->slen = len;
h->text = US s;

return r;
}


/* Walk the given headers strings identifying each header, and construct
a reverse-order list.
*/

static hdr_rlist *
arc_sign_scan_headers(arc_ctx * ctx, gstring * sigheaders)
{
const uschar * s;
hdr_rlist * rheaders = NULL;

s = sigheaders ? sigheaders->s : NULL;
if (s) while (*s)
  {
  const uschar * s2 = s;

  /* This works for either NL or CRLF lines; also nul-termination */
  while (*++s2)
    if (*s2 == '\n' && s2[1] != '\t' && s2[1] != ' ') break;
  s2++;		/* move past end of line */

  rheaders = arc_rlist_entry(rheaders, s, s2 - s);
  s = s2;
  }
return rheaders;
}



/* Return the A-R content, without identity, with line-ending and
NUL termination. */

static BOOL
arc_sign_find_ar(header_line * headers, const uschar * identity, blob * ret)
{
header_line * h;
int ilen = Ustrlen(identity);

ret->data = NULL;
for(h = headers; h; h = h->next)
  {
  uschar * s = h->text, c;
  int len = h->slen;

  if (Ustrncmp(s, HDR_AR, HDRLEN_AR) != 0) continue;
  s += HDRLEN_AR, len -= HDRLEN_AR;		/* header name */
  while (  len > 0
	&& (c = *s) && (c == ' ' || c == '\t' || c == '\r' || c == '\n'))
    s++, len--;					/* FWS */
  if (Ustrncmp(s, identity, ilen) != 0) continue;
  s += ilen; len -= ilen;			/* identity */
  if (len <= 0) continue;
  if ((c = *s) && c == ';') s++, len--;		/* identity terminator */
  while (  len > 0
	&& (c = *s) && (c == ' ' || c == '\t' || c == '\r' || c == '\n'))
    s++, len--;					/* FWS */
  if (len <= 0) continue;
  ret->data = s;
  ret->len = len;
  return TRUE;
  }
return FALSE;
}



/* Append a constructed AAR including CRLF.  Add it to the arc_ctx too.  */

static gstring *
arc_sign_append_aar(gstring * g, arc_ctx * ctx,
  const uschar * identity, int instance, blob * ar)
{
int aar_off = gstring_length(g);
arc_set * as =
  store_get(sizeof(arc_set) + sizeof(arc_line) + sizeof(header_line), GET_UNTAINTED);
arc_line * al = (arc_line *)(as+1);
header_line * h = (header_line *)(al+1);

g = string_catn(g, ARC_HDR_AAR, ARC_HDRLEN_AAR);
g = string_fmt_append(g, " i=%d; %s; smtp.remote-ip=%s;\r\n\t",
			 instance, identity, sender_host_address);
g = string_catn(g, US ar->data, ar->len);

h->slen = g->ptr - aar_off;
h->text = g->s + aar_off;
al->complete = h;
as->next = NULL;
as->prev = ctx->arcset_chain_last;
as->instance = instance;
as->hdr_aar = al;
if (instance == 1)
  ctx->arcset_chain = as;
else
  ctx->arcset_chain_last->next = as;
ctx->arcset_chain_last = as;

DEBUG(D_transport) debug_printf("ARC: AAR '%.*s'\n", h->slen - 2, h->text);
return g;
}



static BOOL
arc_sig_from_pseudoheader(gstring * hdata, int hashtype, const uschar * privkey,
  blob * sig, const uschar * why)
{
hashmethod hm = /*sig->keytype == KEYTYPE_ED25519*/ FALSE
  ? HASH_SHA2_512 : pdkim_hashes[hashtype].exim_hashmethod;
blob hhash;
es_ctx sctx;
const uschar * errstr;

DEBUG(D_transport)
  {
  hctx hhash_ctx;
  debug_printf("ARC: %s header data for signing:\n", why);
  pdkim_quoteprint(hdata->s, hdata->ptr);

  (void) exim_sha_init(&hhash_ctx, pdkim_hashes[hashtype].exim_hashmethod);
  exim_sha_update(&hhash_ctx, hdata->s, hdata->ptr);
  exim_sha_finish(&hhash_ctx, &hhash);
  debug_printf("ARC: header hash: "); pdkim_hexprint(hhash.data, hhash.len);
  }

if (FALSE /*need hash for Ed25519 or GCrypt signing*/ )
  {
  hctx hhash_ctx;
  (void) exim_sha_init(&hhash_ctx, pdkim_hashes[hashtype].exim_hashmethod);
  exim_sha_update(&hhash_ctx, hdata->s, hdata->ptr);
  exim_sha_finish(&hhash_ctx, &hhash);
  }
else
  {
  hhash.data = hdata->s;
  hhash.len = hdata->ptr;
  }

if (  (errstr = exim_dkim_signing_init(privkey, &sctx))
   || (errstr = exim_dkim_sign(&sctx, hm, &hhash, sig)))
  {
  log_write(0, LOG_MAIN, "ARC: %s signing: %s\n", why, errstr);
  DEBUG(D_transport)
    debug_printf("private key, or private-key file content, was: '%s'\n",
      privkey);
  return FALSE;
  }
return TRUE;
}



static gstring *
arc_sign_append_sig(gstring * g, blob * sig)
{
/*debug_printf("%s: raw sig ", __FUNCTION__); pdkim_hexprint(sig->data, sig->len);*/
sig->data = pdkim_encode_base64(sig);
sig->len = Ustrlen(sig->data);
for (;;)
  {
  int len = MIN(sig->len, 74);
  g = string_catn(g, sig->data, len);
  if ((sig->len -= len) == 0) break;
  sig->data += len;
  g = string_catn(g, US"\r\n\t  ", 5);
  }
g = string_catn(g, US";\r\n", 3);
gstring_release_unused(g);
string_from_gstring(g);
return g;
}


/* Append a constructed AMS including CRLF.  Add it to the arc_ctx too. */

static gstring *
arc_sign_append_ams(gstring * g, arc_ctx * ctx, int instance,
  const uschar * identity, const uschar * selector, blob * bodyhash,
  hdr_rlist * rheaders, const uschar * privkey, unsigned options)
{
uschar * s;
gstring * hdata = NULL;
int col;
int hashtype = pdkim_hashname_to_hashtype(US"sha256", 6);	/*XXX hardwired */
blob sig;
int ams_off;
arc_line * al = store_get(sizeof(header_line) + sizeof(arc_line), GET_UNTAINTED);
header_line * h = (header_line *)(al+1);

/* debug_printf("%s\n", __FUNCTION__); */

/* Construct the to-be-signed AMS pseudo-header: everything but the sig. */

ams_off = gstring_length(g);
g = string_fmt_append(g, "%s i=%d; a=rsa-sha256; c=relaxed; d=%s; s=%s",
      ARC_HDR_AMS, instance, identity, selector);	/*XXX hardwired a= */
if (options & ARC_SIGN_OPT_TSTAMP)
  g = string_fmt_append(g, "; t=%lu", (u_long)now);
if (options & ARC_SIGN_OPT_EXPIRE)
  g = string_fmt_append(g, "; x=%lu", (u_long)expire);
g = string_fmt_append(g, ";\r\n\tbh=%s;\r\n\th=",
      pdkim_encode_base64(bodyhash));

for(col = 3; rheaders; rheaders = rheaders->prev)
  {
  const uschar * hnames = US"DKIM-Signature:" PDKIM_DEFAULT_SIGN_HEADERS;
  uschar * name, * htext = rheaders->h->text;
  int sep = ':';

  /* Spot headers of interest */

  while ((name = string_nextinlist(&hnames, &sep, NULL, 0)))
    {
    int len = Ustrlen(name);
    if (strncasecmp(CCS htext, CCS name, len) == 0)
      {
      /* If too long, fold line in h= field */

      if (col + len > 78) g = string_catn(g, US"\r\n\t  ", 5), col = 3;

      /* Add name to h= list */

      g = string_catn(g, name, len);
      g = string_catn(g, US":", 1);
      col += len + 1;

      /* Accumulate header for hashing/signing */

      hdata = string_cat(hdata,
		pdkim_relax_header_n(htext, rheaders->h->slen, TRUE));	/*XXX hardwired */
      break;
      }
    }
  }

/* Lose the last colon from the h= list */

gstring_trim_trailing(g, ':');

g = string_catn(g, US";\r\n\tb=;", 7);

/* Include the pseudo-header in the accumulation */

s = pdkim_relax_header_n(g->s + ams_off, g->ptr - ams_off, FALSE);
hdata = string_cat(hdata, s);

/* Calculate the signature from the accumulation */
/*XXX does that need further relaxation? there are spaces embedded in the b= strings! */

if (!arc_sig_from_pseudoheader(hdata, hashtype, privkey, &sig, US"AMS"))
  return NULL;

/* Lose the trailing semicolon from the psuedo-header, and append the signature
(folded over lines) and termination to complete it. */

gstring_trim(g, 1);
g = arc_sign_append_sig(g, &sig);

h->slen = g->ptr - ams_off;
h->text = g->s + ams_off;
al->complete = h;
ctx->arcset_chain_last->hdr_ams = al;

DEBUG(D_transport) debug_printf("ARC: AMS '%.*s'\n", h->slen - 2, h->text);
return g;
}



/* Look for an arc= result in an A-R header blob.  We know that its data
happens to be a NUL-term string. */

static uschar *
arc_ar_cv_status(blob * ar)
{
const uschar * resinfo = ar->data;
int sep = ';';
uschar * methodspec, * s;

while ((methodspec = string_nextinlist(&resinfo, &sep, NULL, 0)))
  if (Ustrncmp(methodspec, US"arc=", 4) == 0)
    {
    uschar c;
    for (s = methodspec += 4;
         (c = *s) && c != ';' && c != ' ' && c != '\r' && c != '\n'; ) s++;
    return string_copyn(methodspec, s - methodspec);
    }
return US"none";
}



/* Build the AS header and prepend it */

static gstring *
arc_sign_prepend_as(gstring * arcset_interim, arc_ctx * ctx,
  int instance, const uschar * identity, const uschar * selector, blob * ar,
  const uschar * privkey, unsigned options)
{
gstring * arcset;
uschar * status = arc_ar_cv_status(ar);
arc_line * al = store_get(sizeof(header_line) + sizeof(arc_line), GET_UNTAINTED);
header_line * h = (header_line *)(al+1);
uschar * badline_str;

gstring * hdata = NULL;
int hashtype = pdkim_hashname_to_hashtype(US"sha256", 6);	/*XXX hardwired */
blob sig;

/*
- Generate AS
  - no body coverage
  - no h= tag; implicit coverage
  - arc status from A-R
    - if fail:
      - coverage is just the new ARC set
        including self (but with an empty b= in self)
    - if non-fail:
      - all ARC set headers, set-number order, aar then ams then as,
        including self (but with an empty b= in self)
*/
DEBUG(D_transport) debug_printf("ARC: building AS for status '%s'\n", status);

/* Construct the AS except for the signature */

arcset = string_append(NULL, 9,
	  ARC_HDR_AS,
	  US" i=", string_sprintf("%d", instance),
	  US"; cv=", status,
	  US"; a=rsa-sha256; d=", identity,			/*XXX hardwired */
	  US"; s=", selector);					/*XXX same as AMS */
if (options & ARC_SIGN_OPT_TSTAMP)
  arcset = string_append(arcset, 2,
      US"; t=", string_sprintf("%lu", (u_long)now));
arcset = string_cat(arcset,
	  US";\r\n\t b=;");

h->slen = arcset->ptr;
h->text = arcset->s;
al->complete = h;
ctx->arcset_chain_last->hdr_as = al;

/* For any but "fail" chain-verify status, walk the entire chain in order by
instance.  For fail, only the new arc-set.  Accumulate the elements walked. */

for (arc_set * as = Ustrcmp(status, US"fail") == 0
	? ctx->arcset_chain_last : ctx->arcset_chain;
     as; as = as->next)
  {
  arc_line * l;
  /* Accumulate AAR then AMS then AS.  Relaxed canonicalisation
  is required per standard. */

  badline_str = US"aar";
  if (!(l = as->hdr_aar)) goto badline;
  h = l->complete;
  hdata = string_cat(hdata, pdkim_relax_header_n(h->text, h->slen, TRUE));
  badline_str = US"ams";
  if (!(l = as->hdr_ams)) goto badline;
  h = l->complete;
  hdata = string_cat(hdata, pdkim_relax_header_n(h->text, h->slen, TRUE));
  badline_str = US"as";
  if (!(l = as->hdr_as)) goto badline;
  h = l->complete;
  hdata = string_cat(hdata, pdkim_relax_header_n(h->text, h->slen, !!as->next));
  }

/* Calculate the signature from the accumulation */

if (!arc_sig_from_pseudoheader(hdata, hashtype, privkey, &sig, US"AS"))
  return NULL;

/* Lose the trailing semicolon */
arcset->ptr--;
arcset = arc_sign_append_sig(arcset, &sig);
DEBUG(D_transport) debug_printf("ARC: AS  '%.*s'\n", arcset->ptr - 2, arcset->s);

/* Finally, append the AMS and AAR to the new AS */

return string_catn(arcset, arcset_interim->s, arcset_interim->ptr);

badline:
  DEBUG(D_transport)
    debug_printf("ARC: while building AS, missing %s in chain\n", badline_str);
  return NULL;
}


/**************************************/

/* Return pointer to pdkim_bodyhash for given hash method, creating new
method if needed.
*/

void *
arc_ams_setup_sign_bodyhash(void)
{
int canon_head, canon_body;

DEBUG(D_transport) debug_printf("ARC: requesting bodyhash\n");
pdkim_cstring_to_canons(US"relaxed", 7, &canon_head, &canon_body);	/*XXX hardwired */
return pdkim_set_bodyhash(&dkim_sign_ctx,
	pdkim_hashname_to_hashtype(US"sha256", 6),			/*XXX hardwired */
	canon_body,
	-1);
}



void
arc_sign_init(void)
{
memset(&arc_sign_ctx, 0, sizeof(arc_sign_ctx));
headers_rlist = NULL;
}



/* A "normal" header line, identified by DKIM processing.  These arrive before
the call to arc_sign(), which carries any newly-created DKIM headers - and
those go textually before the normal ones in the message.

We have to take the feed from DKIM as, in the transport-filter case, the
headers are not in memory at the time of the call to arc_sign().

Take a copy of the header and construct a reverse-order list.
Also parse ARC-chain headers and build the chain struct, retaining pointers
into the copies.
*/

static const uschar *
arc_header_sign_feed(gstring * g)
{
uschar * s = string_copy_from_gstring(g);
headers_rlist = arc_rlist_entry(headers_rlist, s, g->ptr);
return arc_try_header(&arc_sign_ctx, headers_rlist->h, TRUE);
}



/* Per RFCs 6376, 7489 the only allowed chars in either an ADMD id
or a selector are ALPHA/DIGGIT/'-'/'.'

Check, to help catch misconfigurations such as a missing selector
element in the arc_sign list.
*/

static BOOL
arc_valid_id(const uschar * s)
{
for (uschar c; c = *s++; )
  if (!isalnum(c) && c != '-' && c != '.') return FALSE;
return TRUE;
}



/* ARC signing.  Called from the smtp transport, if the arc_sign option is set.
The dkim_exim_sign() function has already been called, so will have hashed the
message body for us so long as we requested a hash previously.

Arguments:
  signspec	Three-element colon-sep list: identity, selector, privkey.
		Optional fourth element: comma-sep list of options.
		Already expanded
  sigheaders	Any signature headers already generated, eg. by DKIM, or NULL
  errstr	Error string

Return value
  Set of headers to prepend to the message, including the supplied sigheaders
  but not the plainheaders.
*/

gstring *
arc_sign(const uschar * signspec, gstring * sigheaders, uschar ** errstr)
{
const uschar * identity, * selector, * privkey, * opts, * s;
unsigned options = 0;
int sep = 0;
header_line * headers;
hdr_rlist * rheaders;
blob ar;
int instance;
gstring * g = NULL;
pdkim_bodyhash * b;

expire = now = 0;

/* Parse the signing specification */

if (!(identity = string_nextinlist(&signspec, &sep, NULL, 0)) || !*identity)
  { s = US"identity"; goto bad_arg_ret; }
if (!(selector = string_nextinlist(&signspec, &sep, NULL, 0)) || !*selector)
  { s = US"selector"; goto bad_arg_ret; }
if (!(privkey = string_nextinlist(&signspec, &sep, NULL, 0))  || !*privkey)
  { s = US"privkey"; goto bad_arg_ret; }
if (!arc_valid_id(identity))
  { s = US"identity"; goto bad_arg_ret; }
if (!arc_valid_id(selector))
  { s = US"selector"; goto bad_arg_ret; }
if (*privkey == '/' && !(privkey = expand_file_big_buffer(privkey)))
  goto ret_sigheaders;

if ((opts = string_nextinlist(&signspec, &sep, NULL, 0)))
  {
  int osep = ',';
  while ((s = string_nextinlist(&opts, &osep, NULL, 0)))
    if (Ustrcmp(s, "timestamps") == 0)
      {
      options |= ARC_SIGN_OPT_TSTAMP;
      if (!now) now = time(NULL);
      }
    else if (Ustrncmp(s, "expire", 6) == 0)
      {
      options |= ARC_SIGN_OPT_EXPIRE;
      if (*(s += 6) == '=')
	if (*++s == '+')
	  {
	  if (!(expire = (time_t)atoi(CS ++s)))
	    expire = ARC_SIGN_DEFAULT_EXPIRE_DELTA;
	  if (!now) now = time(NULL);
	  expire += now;
	  }
	else
	  expire = (time_t)atol(CS s);
      else
	{
	if (!now) now = time(NULL);
	expire = now + ARC_SIGN_DEFAULT_EXPIRE_DELTA;
	}
      }
  }

DEBUG(D_transport) debug_printf("ARC: sign for %s\n", identity);

/* Make an rlist of any new DKIM headers, then add the "normals" rlist to it.
Then scan the list for an A-R header. */

string_from_gstring(sigheaders);
if ((rheaders = arc_sign_scan_headers(&arc_sign_ctx, sigheaders)))
  {
  hdr_rlist ** rp;
  for (rp = &headers_rlist; *rp; ) rp = &(*rp)->prev;
  *rp = rheaders;
  }

/* Finally, build a normal-order headers list */
/*XXX only needed for hunt-the-AR? */
/*XXX also, we really should be accepting any number of ADMD-matching ARs */
  {
  header_line * hnext = NULL;
  for (rheaders = headers_rlist; rheaders;
       hnext = rheaders->h, rheaders = rheaders->prev)
    rheaders->h->next = hnext;
  headers = hnext;
  }

if (!(arc_sign_find_ar(headers, identity, &ar)))
  {
  log_write(0, LOG_MAIN, "ARC: no Authentication-Results header for signing");
  goto ret_sigheaders;
  }

/* We previously built the data-struct for the existing ARC chain, if any, using a headers
feed from the DKIM module.  Use that to give the instance number for the ARC set we are
about to build. */

DEBUG(D_transport)
  if (arc_sign_ctx.arcset_chain_last)
    debug_printf("ARC: existing chain highest instance: %d\n",
      arc_sign_ctx.arcset_chain_last->instance);
  else
    debug_printf("ARC: no existing chain\n");

instance = arc_sign_ctx.arcset_chain_last ? arc_sign_ctx.arcset_chain_last->instance + 1 : 1;

/*
- Generate AAR
  - copy the A-R; prepend i= & identity
*/

g = arc_sign_append_aar(g, &arc_sign_ctx, identity, instance, &ar);

/*
- Generate AMS
  - Looks fairly like a DKIM sig
  - Cover all DKIM sig headers as well as the usuals
    - ? oversigning?
  - Covers the data
  - we must have requested a suitable bodyhash previously
*/

b = arc_ams_setup_sign_bodyhash();
g = arc_sign_append_ams(g, &arc_sign_ctx, instance, identity, selector,
      &b->bh, headers_rlist, privkey, options);

/*
- Generate AS
  - no body coverage
  - no h= tag; implicit coverage
  - arc status from A-R
    - if fail:
      - coverage is just the new ARC set
        including self (but with an empty b= in self)
    - if non-fail:
      - all ARC set headers, set-number order, aar then ams then as,
        including self (but with an empty b= in self)
*/

if (g)
  g = arc_sign_prepend_as(g, &arc_sign_ctx, instance, identity, selector, &ar,
      privkey, options);

/* Finally, append the dkim headers and return the lot. */

if (sigheaders) g = string_catn(g, sigheaders->s, sigheaders->ptr);

out:
  if (!g) return string_get(1);
  (void) string_from_gstring(g);
  gstring_release_unused(g);
  return g;


bad_arg_ret:
  log_write(0, LOG_MAIN, "ARC: bad signing-specification (%s)", s);
ret_sigheaders:
  g = sigheaders;
  goto out;
}


/******************************************************************************/

/* Check to see if the line is an AMS and if so, set up to validate it.
Called from the DKIM input processing.  This must be done now as the message
body data is hashed during input.

We call the DKIM code to request a body-hash; it has the facility already
and the hash parameters might be common with other requests.
*/

static const uschar *
arc_header_vfy_feed(gstring * g)
{
header_line h;
arc_line al;
pdkim_bodyhash * b;
uschar * errstr;

if (!dkim_verify_ctx) return US"no dkim context";

if (strncmpic(ARC_HDR_AMS, g->s, ARC_HDRLEN_AMS) != 0) return US"not AMS";

DEBUG(D_receive) debug_printf("ARC: spotted AMS header\n");
/* Parse the AMS header */

memset(&al, 0, sizeof(arc_line));
h.next = NULL;
h.slen = len_string_from_gstring(g, &h.text);
if ((errstr = arc_parse_line(&al, &h, ARC_HDRLEN_AMS, le_all)))
  {
  DEBUG(D_acl) if (errstr) debug_printf("ARC: %s\n", errstr);
  goto badline;
  }

if (!al.a_hash.data)
  {
  DEBUG(D_acl) debug_printf("ARC: no a_hash from '%.*s'\n", h.slen, h.text);
  goto badline;
  }

/* defaults */
if (!al.c.data)
  {
  al.c_body.data = US"simple"; al.c_body.len = 6;
  al.c_head = al.c_body;
  }

/* Ask the dkim code to calc a bodyhash with those specs */

if (!(b = arc_ams_setup_vfy_bodyhash(&al)))
  return US"dkim hash setup fail";

/* Discard the reference; search again at verify time, knowing that one
should have been created here. */

return NULL;

badline:
  return US"line parsing error";
}



/* A header line has been identified by DKIM processing.

Arguments:
  g		Header line
  is_vfy	TRUE for verify mode or FALSE for signing mode

Return:
  NULL for success, or an error string (probably unused)
*/

const uschar *
arc_header_feed(gstring * g, BOOL is_vfy)
{
return is_vfy ? arc_header_vfy_feed(g) : arc_header_sign_feed(g);
}



/******************************************************************************/

/* Construct the list of domains from the ARC chain after validation */

uschar *
fn_arc_domains(void)
{
arc_set * as;
unsigned inst;
gstring * g = NULL;

for (as = arc_verify_ctx.arcset_chain, inst = 1; as; as = as->next, inst++)
  {
  arc_line * hdr_as = as->hdr_as;
  if (hdr_as)
    {
    blob * d = &hdr_as->d;

    for (; inst < as->instance; inst++)
      g = string_catn(g, US":", 1);

    g = d->data && d->len
      ? string_append_listele_n(g, ':', d->data, d->len)
      : string_catn(g, US":", 1);
    }
  else
    g = string_catn(g, US":", 1);
  }
if (!g) return US"";
return string_from_gstring(g);
}


/* Construct an Authentication-Results header portion, for the ARC module */

gstring *
authres_arc(gstring * g)
{
if (arc_state)
  {
  arc_line * highest_ams;
  int start = 0;		/* Compiler quietening */
  DEBUG(D_acl) start = gstring_length(g);

  g = string_append(g, 2, US";\n\tarc=", arc_state);
  if (arc_received_instance > 0)
    {
    g = string_fmt_append(g, " (i=%d)", arc_received_instance);
    if (arc_state_reason)
      g = string_append(g, 3, US"(", arc_state_reason, US")");
    g = string_catn(g, US" header.s=", 10);
    highest_ams = arc_received->hdr_ams;
    g = string_catn(g, highest_ams->s.data, highest_ams->s.len);

    g = string_fmt_append(g, " arc.oldest-pass=%d", arc_oldest_pass);

    if (sender_host_address)
      g = string_append(g, 2, US" smtp.remote-ip=", sender_host_address);
    }
  else if (arc_state_reason)
    g = string_append(g, 3, US" (", arc_state_reason, US")");
  DEBUG(D_acl) debug_printf("ARC:\tauthres '%.*s'\n",
		  gstring_length(g) - start - 3, g->s + start + 3);
  }
else
  DEBUG(D_acl) debug_printf("ARC:\tno authres\n");
return g;
}


#  ifdef SUPPORT_DMARC
/* Append a DMARC history record pair for ARC, to the given history set */

gstring *
arc_dmarc_hist_append(gstring * g)
{
if (arc_state)
  {
  BOOL first = TRUE;
  int i = Ustrcmp(arc_state, "pass") == 0 ? ARES_RESULT_PASS
	  : Ustrcmp(arc_state, "fail") == 0 ? ARES_RESULT_FAIL
	  : ARES_RESULT_UNKNOWN;
  g = string_fmt_append(g, "arc %d\n", i);
  g = string_fmt_append(g, "arc_policy %d json[",
			  i == ARES_RESULT_PASS ? DMARC_ARC_POLICY_RESULT_PASS
			  : i == ARES_RESULT_FAIL ? DMARC_ARC_POLICY_RESULT_FAIL
			  : DMARC_ARC_POLICY_RESULT_UNUSED);
  /*XXX would we prefer this backwards? */
  for (arc_set * as = arc_verify_ctx.arcset_chain; as;
	as = as->next, first = FALSE)
    {
    arc_line * line = as->hdr_as;
    if (line)
      {
      blob * d = &line->d;
      blob * s = &line->s;

      if (!first)
	g = string_catn(g, US",", 1);

      g = string_fmt_append(g, " (\"i\":%u,"			/*)*/
				" \"d\":\"%.*s\","
				" \"s\":\"%.*s\"",
		  as->instance,
		  d->data ? (int)d->len : 0, d->data && d->len ? d->data : US"",
		  s->data ? (int)s->len : 0, s->data && s->len ? s->data : US""
			   );
      if ((line = as->hdr_aar))
	{
	blob * ip = &line->ip;
	if (ip->data && ip->len)
	  g = string_fmt_append(g, ", \"ip\":\"%.*s\"", (int)ip->len, ip->data);
	}

      g = string_catn(g, US")", 1);
      }
    }
  g = string_catn(g, US" ]\n", 3);
  }
else
  g = string_fmt_append(g, "arc %d\narc_policy %d json:[]\n",
			ARES_RESULT_UNKNOWN, DMARC_ARC_POLICY_RESULT_UNUSED);
return g;
}
#  endif


# endif /* DISABLE_DKIM */
#endif /* EXPERIMENTAL_ARC */
/* vi: aw ai sw=2
 */
