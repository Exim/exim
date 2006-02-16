/* $Cambridge: exim/test/src/fakens.c,v 1.2 2006/02/16 10:05:34 ph10 Exp $ */

/*************************************************
*       fakens - A Fake Nameserver Program       *
*************************************************/

/* This program exists to support the testing of DNS handling code in Exim. It
avoids the need to install special zones in a real nameserver. When Exim is
running in its (new) test harness, DNS lookups are first passed to this program
instead of to the real resolver. (With a few exceptions - see the discussion in
the test suite's README file.) The program is also passed the name of the Exim
spool directory; it expects to find its "zone files" in ../dnszones relative to
that directory. Note that there is little checking in this program. The fake
zone files are assumed to be syntactically valid.

The zones that are handled are found by scanning the dnszones directory. A file
whose name is of the form db.ip4.x is a zone file for .x.in-addr.arpa; a file
whose name is of the form db.ip6.x is a zone file for .x.ip6.arpa; a file of
the form db.anything.else is a zone file for .anything.else. A file of the form
qualify.x.y specifies the domain that is used to qualify single-component
names, except for the name "dontqualify".

The arguments to the program are:

  the name of the Exim spool directory
  the domain name that is being sought
  the DNS record type that is being sought

The output from the program is written to stdout. It is supposed to be in
exactly the same format as a traditional namserver response (see RFC 1035) so
that Exim can process it as normal. At present, no compression is used.
Error messages are written to stderr.

The return codes from the program are zero for success, and otherwise the
values that are set in h_errno after a failing call to the normal resolver:

  1 HOST_NOT_FOUND     host not found (authoritative)
  2 TRY_AGAIN          server failure
  3 NO_RECOVERY        non-recoverable error
  4 NO_DATA            valid name, no data of requested type

In a real nameserver, TRY_AGAIN is also used for a non-authoritative not found,
but it is not used for that here. There is also one extra return code:

  5 PASS_ON            requests Exim to call res_search()

This is used for zones that fakens does not recognize. It is also used if a
line in the zone file contains exactly this:

  PASS ON NOT FOUND

and the domain is not found. It converts the the result to PASS_ON instead of
HOST_NOT_FOUND. */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/nameser.h>
#include <sys/types.h>
#include <dirent.h>

#define FALSE         0
#define TRUE          1
#define PASS_ON       5

typedef int BOOL;
typedef unsigned char uschar;

#define CS   (char *)
#define CCS  (const char *)
#define US   (unsigned char *)

#define Ustrcat(s,t)       strcat(CS(s),CCS(t))
#define Ustrchr(s,n)       US strchr(CCS(s),n)
#define Ustrcmp(s,t)       strcmp(CCS(s),CCS(t))
#define Ustrcpy(s,t)       strcpy(CS(s),CCS(t))
#define Ustrlen(s)         (int)strlen(CCS(s))
#define Ustrncmp(s,t,n)    strncmp(CCS(s),CCS(t),n)
#define Ustrncpy(s,t,n)    strncpy(CS(s),CCS(t),n)

typedef struct zoneitem {
  uschar *zone;
  uschar *zonefile;
} zoneitem;

typedef struct tlist {
  uschar *name;
  int value;
} tlist;

/* On some (older?) operating systems, the standard ns_t_xxx definitions are
not available, and only the older T_xxx ones exist in nameser.h. If ns_t_a is
not defined, assume we are in this state. A really old system might not even
know about AAAA and SRV at all. */

#ifndef ns_t_a
#define ns_t_a      T_A
#define ns_t_ns     T_NS
#define ns_t_cname  T_CNAME
#define ns_t_soa    T_SOA
#define ns_t_ptr    T_PTR
#define ns_t_mx     T_MX
#define ns_t_txt    T_TXT
#define ns_t_aaaa   T_AAAA
#define ns_t_srv    T_SRV
#ifndef T_AAAA
#define T_AAAA      28
#endif
#ifndef T_SRV
#define T_SRV       33
#endif
#endif

static tlist type_list[] = {
  { US"A",       ns_t_a },
  { US"NS",      ns_t_ns },
  { US"CNAME",   ns_t_cname },
/*  { US"SOA",     ns_t_soa },  Not currently in use */
  { US"PTR",     ns_t_ptr },
  { US"MX",      ns_t_mx },
  { US"TXT",     ns_t_txt },
  { US"AAAA",    ns_t_aaaa },
  { US"SRV",     ns_t_srv },
  { NULL,        0 }
};



/*************************************************
*           Get memory and sprintf into it       *
*************************************************/

/* This is used when building a table of zones and their files.

Arguments:
  format       a format string
  ...          arguments

Returns:       pointer to formatted string
*/

static uschar *
fcopystring(uschar *format, ...)
{
uschar *yield;
char buffer[256];
va_list ap;
va_start(ap, format);
vsprintf(buffer, format, ap);
va_end(ap);
yield = (uschar *)malloc(Ustrlen(buffer) + 1);
Ustrcpy(yield, buffer);
return yield;
}


/*************************************************
*             Pack name into memory              *
*************************************************/

/* This function packs a domain name into memory according to DNS rules. At
present, it doesn't do any compression.

Arguments:
  name         the name
  pk           where to put it

Returns:       the updated value of pk
*/

static uschar *
packname(uschar *name, uschar *pk)
{
while (*name != 0)
  {
  uschar *p = name;
  while (*p != 0 && *p != '.') p++;
  *pk++ = (p - name);
  memmove(pk, name, p - name);
  pk += p - name;
  name = (*p == 0)? p : p + 1;
  }
*pk++ = 0;
return pk;
}



/*************************************************
*              Scan file for RRs                 *
*************************************************/

/* This function scans an open "zone file" for appropriate records, and adds
any that are found to the output buffer.

Arguments:
  f           the input FILE
  zone        the current zone name
  domain      the domain we are looking for
  qtype       the type of RR we want
  qtypelen    the length of qtype
  pkptr       points to the output buffer pointer; this is updated
  countptr    points to the record count; this is updated

Returns:      0 on success, else HOST_NOT_FOUND or NO_DATA or NO_RECOVERY or
              PASS_ON - the latter if a "PASS ON NOT FOUND" line is seen
*/

static int
find_records(FILE *f, uschar *zone, uschar *domain, uschar *qtype,
  int qtypelen, uschar **pkptr, int *countptr)
{
int yield = HOST_NOT_FOUND;
int domainlen = Ustrlen(domain);
BOOL pass_on_not_found = FALSE;
tlist *typeptr;
uschar *pk = *pkptr;
uschar buffer[256];
uschar rrdomain[256];
uschar RRdomain[256];

/* Decode the required type */

for (typeptr = type_list; typeptr->name != NULL; typeptr++)
  { if (Ustrcmp(typeptr->name, qtype) == 0) break; }
if (typeptr->name == NULL)
  {
  fprintf(stderr, "fakens: unknown record type %s\n", qtype);
  return NO_RECOVERY;
  }

rrdomain[0] = 0;                 /* No previous domain */
(void)fseek(f, 0, SEEK_SET);     /* Start again at the beginning */

/* Scan for RRs */

while (fgets(CS buffer, sizeof(buffer), f) != NULL)
  {
  uschar *rdlptr;
  uschar *p, *ep, *pp;
  BOOL found_cname = FALSE;
  int i, plen, value;
  int tvalue = typeptr->value;
  int qtlen = qtypelen;

  p = buffer;
  while (isspace(*p)) p++;
  if (*p == 0 || *p == ';') continue;

  if (Ustrncmp(p, "PASS ON NOT FOUND", 17) == 0)
    {
    pass_on_not_found = TRUE;
    continue;
    }

  ep = buffer + Ustrlen(buffer);
  while (isspace(ep[-1])) ep--;
  *ep = 0;

  p = buffer;
  if (!isspace(*p))
    {
    uschar *pp = rrdomain;
    uschar *PP = RRdomain;
    while (!isspace(*p))
      {
      *pp++ = tolower(*p);
      *PP++ = *p++;
      }
    if (pp[-1] != '.')
      {
      Ustrcpy(pp, zone);
      Ustrcpy(PP, zone);
      }
    else
      {
      pp[-1] = 0;
      PP[-1] = 0;
      }
    }

  /* Compare domain names; first check for a wildcard */

  if (rrdomain[0] == '*')
    {
    int restlen = Ustrlen(rrdomain) - 1;
    if (domainlen > restlen &&
        Ustrcmp(domain + domainlen - restlen, rrdomain + 1) != 0) continue;
    }

  /* Not a wildcard RR */

  else if (Ustrcmp(domain, rrdomain) != 0) continue;

  /* The domain matches */

  if (yield == HOST_NOT_FOUND) yield = NO_DATA;

  /* Compare RR types; a CNAME record is always returned */

  while (isspace(*p)) p++;

  if (Ustrncmp(p, "CNAME", 5) == 0)
    {
    tvalue = ns_t_cname;
    qtlen = 5;
    found_cname = TRUE;
    }
  else if (Ustrncmp(p, qtype, qtypelen) != 0 || !isspace(p[qtypelen])) continue;

  /* Found a relevant record */

  yield = 0;
  *countptr = *countptr + 1;

  p += qtlen;
  while (isspace(*p)) p++;

  /* For a wildcard record, use the search name; otherwise use the record's
  name in its original case because it might contain upper case letters. */

  pk = packname((rrdomain[0] == '*')? domain : RRdomain, pk);
  *pk++ = (tvalue >> 8) & 255;
  *pk++ = (tvalue) & 255;
  *pk++ = 0;
  *pk++ = 1;     /* class = IN */

  pk += 4;       /* TTL field; don't care */

  rdlptr = pk;   /* remember rdlength field */
  pk += 2;

  /* The rest of the data depends on the type */

  switch (tvalue)
    {
    case ns_t_soa:  /* Not currently used */
    break;

    case ns_t_a:
    for (i = 0; i < 4; i++)
      {
      value = 0;
      while (isdigit(*p)) value = value*10 + *p++ - '0';
      *pk++ = value;
      p++;
      }
    break;

    /* The only occurrence of a double colon is for ::1 */
    case ns_t_aaaa:
    if (Ustrcmp(p, "::1") == 0)
      {
      memset(pk, 0, 15);
      pk += 15;
      *pk++ = 1;
      }
    else for (i = 0; i < 8; i++)
      {
      value = 0;
      while (isxdigit(*p))
        {
        value = value * 16 + toupper(*p) - (isdigit(*p)? '0' : '7');
        p++;
        }
      *pk++ = (value >> 8) & 255;
      *pk++ = value & 255;
      p++;
      }
    break;

    case ns_t_mx:
    value = 0;
    while (isdigit(*p)) value = value*10 + *p++ - '0';
    while (isspace(*p)) p++;
    *pk++ = (value >> 8) & 255;
    *pk++ = value & 255;
    if (ep[-1] != '.') sprintf(ep, "%s.", zone);
    pk = packname(p, pk);
    plen = Ustrlen(p);
    break;

    case ns_t_txt:
    pp = pk++;
    if (*p == '"') p++;   /* Should always be the case */
    while (*p != 0 && *p != '"') *pk++ = *p++;
    *pp = pk - pp - 1;
    break;

    case ns_t_srv:
    for (i = 0; i < 3; i++)
      {
      value = 0;
      while (isdigit(*p)) value = value*10 + *p++ - '0';
      while (isspace(*p)) p++;
      *pk++ = (value >> 8) & 255;
      *pk++ = value & 255;
      }

    /* Fall through */

    case ns_t_cname:
    case ns_t_ns:
    case ns_t_ptr:
    if (ep[-1] != '.') sprintf(ep, "%s.", zone);
    pk = packname(p, pk);
    plen = Ustrlen(p);
    break;
    }

  /* Fill in the length, and we are done with this RR */

  rdlptr[0] = ((pk - rdlptr - 2) >> 8) & 255;
  rdlptr[1] = (pk -rdlptr - 2) & 255;

  /* If we have just yielded a CNAME, we must change the domain name to the
  new domain, and re-start the scan from the beginning. */

  if (found_cname)
    {
    domain = fcopystring("%s", p);
    domainlen = Ustrlen(domain);
    domain[domainlen - 1] = 0;       /* Removed trailing dot */
    rrdomain[0] = 0;                 /* No previous domain */
    (void)fseek(f, 0, SEEK_SET);     /* Start again at the beginning */
    }
  }

*pkptr = pk;
return (yield == HOST_NOT_FOUND && pass_on_not_found)? PASS_ON : yield;
}



/*************************************************
*           Entry point and main program         *
*************************************************/

int
main(int argc, char **argv)
{
FILE *f;
DIR *d;
int domlen, qtypelen;
int yield, count;
int i;
int zonecount = 0;
struct dirent *de;
zoneitem zones[32];
uschar *qualify = NULL;
uschar *p, *zone;
uschar *zonefile = NULL;
uschar domain[256];
uschar buffer[256];
uschar qtype[12];
uschar packet[512];
uschar *pk = packet;

if (argc != 4)
  {
  fprintf(stderr, "fakens: expected 3 arguments, received %d\n", argc-1);
  return NO_RECOVERY;
  }

/* Find the zones */

(void)sprintf(buffer, "%s/../dnszones", argv[1]);

d = opendir(CCS buffer);
if (d == NULL)
  {
  fprintf(stderr, "fakens: failed to opendir %s: %s\n", buffer,
    strerror(errno));
  return NO_RECOVERY;
  }

while ((de = readdir(d)) != NULL)
  {
  uschar *name = de->d_name;
  if (Ustrncmp(name, "qualify.", 8) == 0)
    {
    qualify = fcopystring("%s", name + 7);
    continue;
    }
  if (Ustrncmp(name, "db.", 3) != 0) continue;
  if (Ustrncmp(name + 3, "ip4.", 4) == 0)
    zones[zonecount].zone = fcopystring("%s.in-addr.arpa", name + 6);
  else if (Ustrncmp(name + 3, "ip6.", 4) == 0)
    zones[zonecount].zone = fcopystring("%s.ip6.arpa", name + 6);
  else
    zones[zonecount].zone = fcopystring("%s", name + 2);
  zones[zonecount++].zonefile = fcopystring("%s", name);
  }
(void)closedir(d);

/* Get the RR type and upper case it, and check that we recognize it. */

Ustrncpy(qtype, argv[3], sizeof(qtype));
qtypelen = Ustrlen(qtype);
for (p = qtype; *p != 0; p++) *p = toupper(*p);

/* Find the domain, lower case it, check that it is in a zone that we handle,
and set up the zone file name. The zone names in the table all start with a
dot. */

domlen = Ustrlen(argv[2]);
if (argv[2][domlen-1] == '.') domlen--;
Ustrncpy(domain, argv[2], domlen);
domain[domlen] = 0;
for (i = 0; i < domlen; i++) domain[i] = tolower(domain[i]);

if (Ustrchr(domain, '.') == NULL && qualify != NULL &&
    Ustrcmp(domain, "dontqualify") != 0)
  {
  Ustrcat(domain, qualify);
  domlen += Ustrlen(qualify);
  }

for (i = 0; i < zonecount; i++)
  {
  int zlen;
  zone = zones[i].zone;
  zlen = Ustrlen(zone);
  if (Ustrcmp(domain, zone+1) == 0 || (domlen >= zlen &&
      Ustrcmp(domain + domlen - zlen, zone) == 0))
    {
    zonefile = zones[i].zonefile;
    break;
    }
  }

if (zonefile == NULL)
  {
  fprintf(stderr, "fakens: query not in faked zone: domain is: %s\n", domain);
  return PASS_ON;
  }

(void)sprintf(buffer, "%s/../dnszones/%s", argv[1], zonefile);

/* Initialize the start of the response packet. We don't have to fake up
everything, because we know that Exim will look only at the answer and
additional section parts. */

memset(packet, 0, 12);
pk += 12;

/* Open the zone file. */

f = fopen(buffer, "r");
if (f == NULL)
  {
  fprintf(stderr, "fakens: failed to open %s: %s\n", buffer, strerror(errno));
  return NO_RECOVERY;
  }

/* Find the records we want, and add them to the result. */

count = 0;
yield = find_records(f, zone, domain, qtype, qtypelen, &pk, &count);
if (yield == NO_RECOVERY) goto END_OFF;

packet[6] = (count >> 8) & 255;
packet[7] = count & 255;

/* There is no need to return any additional records because Exim no longer
(from release 4.61) makes any use of them. */

packet[10] = 0;
packet[11] = 0;

/* Close the zone file, write the result, and return. */

END_OFF:
(void)fclose(f);
(void)fwrite(packet, 1, pk - packet, stdout);
return yield;
}

/* End of fakens.c */
