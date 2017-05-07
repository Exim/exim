/*************************************************
*       fakens - A Fake Nameserver Program       *
*************************************************/

/* This program exists to support the testing of DNS handling code in Exim. It
avoids the need to install special zones in a real nameserver. When Exim is
running in its (new) test harness, DNS lookups are first passed to this program
instead of to the real resolver. (With a few exceptions - see the discussion in
the test suite's README file.) The program is also passed the name of the Exim
spool directory; it expects to find its "zone files" in dnszones relative to
exim config_main_directory. Note that there is little checking in this program. The fake
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
exactly the same format as a traditional nameserver response (see RFC 1035) so
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
HOST_NOT_FOUND.

Any DNS record line in a zone file can be prefixed with "DELAY=" and
a number of milliseconds (followed by one space).

Any DNS record line can be prefixed with "DNSSEC ";
if all the records found by a lookup are marked
as such then the response will have the "AD" bit set.

Any DNS record line can be prefixed with "NXDOMAIN ";
The record will be ignored (but the prefix set still applied);
This lets us return a DNSSEC NXDOMAIN.

Any DNS record line can be prefixed with "AA "
if all the records found by a lookup are marked
as such then the response will have the "AA" bit set.

Any DNS record line in a zone file can be prefixed with "TTL=" and
a number of seconds (followed by one space).

*/

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

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
#define Ustrtok(s,t)       (uschar*)strtok(CS(s),CCS(t))

typedef struct zoneitem {
  uschar *zone;
  uschar *zonefile;
} zoneitem;

typedef struct tlist {
  uschar *name;
  int value;
} tlist;

#define DEFAULT_TTL 3600U

/* On some (older?) operating systems, the standard ns_t_xxx definitions are
not available, and only the older T_xxx ones exist in nameser.h. If ns_t_a is
not defined, assume we are in this state. A really old system might not even
know about AAAA and SRV at all. */

#ifndef ns_t_a
# define ns_t_a      T_A
# define ns_t_ns     T_NS
# define ns_t_cname  T_CNAME
# define ns_t_soa    T_SOA
# define ns_t_ptr    T_PTR
# define ns_t_mx     T_MX
# define ns_t_txt    T_TXT
# define ns_t_aaaa   T_AAAA
# define ns_t_srv    T_SRV
# define ns_t_tlsa   T_TLSA
# ifndef T_AAAA
#  define T_AAAA      28
# endif
# ifndef T_SRV
#  define T_SRV       33
# endif
# ifndef T_TLSA
#  define T_TLSA      52
# endif
#endif

static tlist type_list[] = {
  { US"A",       ns_t_a },
  { US"NS",      ns_t_ns },
  { US"CNAME",   ns_t_cname },
  { US"SOA",     ns_t_soa },
  { US"PTR",     ns_t_ptr },
  { US"MX",      ns_t_mx },
  { US"TXT",     ns_t_txt },
  { US"AAAA",    ns_t_aaaa },
  { US"SRV",     ns_t_srv },
  { US"TLSA",    ns_t_tlsa },
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
vsprintf(buffer, CS format, ap);
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

uschar *
bytefield(uschar ** pp, uschar * pk)
{
unsigned value = 0;
uschar * p = *pp;

while (isdigit(*p)) value = value*10 + *p++ - '0';
while (isspace(*p)) p++;
*pp = p;
*pk++ = value & 255;
return pk;
}

uschar *
shortfield(uschar ** pp, uschar * pk)
{
unsigned value = 0;
uschar * p = *pp;

while (isdigit(*p)) value = value*10 + *p++ - '0';
while (isspace(*p)) p++;
*pp = p;
*pk++ = (value >> 8) & 255;
*pk++ = value & 255;
return pk;
}

uschar *
longfield(uschar ** pp, uschar * pk)
{
unsigned long value = 0;
uschar * p = *pp;

while (isdigit(*p)) value = value*10 + *p++ - '0';
while (isspace(*p)) p++;
*pp = p;
*pk++ = (value >> 24) & 255;
*pk++ = (value >> 16) & 255;
*pk++ = (value >> 8) & 255;
*pk++ = value & 255;
return pk;
}



/*************************************************/

static void
milliwait(struct itimerval *itval)
{
sigset_t sigmask;
sigset_t old_sigmask;

if (itval->it_value.tv_usec < 100 && itval->it_value.tv_sec == 0)
  return;
(void)sigemptyset(&sigmask);                           /* Empty mask */
(void)sigaddset(&sigmask, SIGALRM);                    /* Add SIGALRM */
(void)sigprocmask(SIG_BLOCK, &sigmask, &old_sigmask);  /* Block SIGALRM */
(void)setitimer(ITIMER_REAL, itval, NULL);             /* Start timer */
(void)sigfillset(&sigmask);                            /* All signals */
(void)sigdelset(&sigmask, SIGALRM);                    /* Remove SIGALRM */
(void)sigsuspend(&sigmask);                            /* Until SIGALRM */
(void)sigprocmask(SIG_SETMASK, &old_sigmask, NULL);    /* Restore mask */
}

static void
millisleep(int msec)
{
struct itimerval itval;
itval.it_interval.tv_sec = 0;
itval.it_interval.tv_usec = 0;
itval.it_value.tv_sec = msec/1000;
itval.it_value.tv_usec = (msec % 1000) * 1000;
milliwait(&itval);
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
  dnssec      points to the AD flag indicator; this is updated
  aa          points to the AA flag indicator; this is updated

Returns:      0 on success, else HOST_NOT_FOUND or NO_DATA or NO_RECOVERY or
              PASS_ON - the latter if a "PASS ON NOT FOUND" line is seen
*/

static int
find_records(FILE *f, uschar *zone, uschar *domain, uschar *qtype,
  int qtypelen, uschar **pkptr, int *countptr, BOOL * dnssec, BOOL * aa)
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
  int i, value;
  int tvalue = typeptr->value;
  int qtlen = qtypelen;
  BOOL rr_sec = FALSE;
  BOOL rr_aa = FALSE;
  BOOL rr_ignore = FALSE;
  int delay = 0;
  uint ttl = DEFAULT_TTL;

  p = buffer;
  while (isspace(*p)) p++;
  if (*p == 0 || *p == ';') continue;

  if (Ustrncmp(p, US"PASS ON NOT FOUND", 17) == 0)
    {
    pass_on_not_found = TRUE;
    continue;
    }

  ep = buffer + Ustrlen(buffer);
  while (isspace(ep[-1])) ep--;
  *ep = 0;

  p = buffer;
  for (;;)
    {
    if (Ustrncmp(p, US"DNSSEC ", 7) == 0)       /* tagged as secure */
      {
      rr_sec = TRUE;
      p += 7;
      }
    if (Ustrncmp(p, US"NXDOMAIN ", 9) == 0)     /* ignore record content */
      {
      rr_ignore = TRUE;
      p += 9;
      }
    else if (Ustrncmp(p, US"AA ", 3) == 0)      /* tagged as authoritative */
      {
      rr_aa = TRUE;
      p += 3;
      }
    else if (Ustrncmp(p, US"DELAY=", 6) == 0)   /* delay before response */
      {
      for (p += 6; *p >= '0' && *p <= '9'; p++) delay = delay*10 + *p - '0';
      if (isspace(*p)) p++;
      }
    else if (Ustrncmp(p, US"TTL=", 4) == 0)     /* TTL for record */
      {
      ttl = 0;
      for (p += 4; *p >= '0' && *p <= '9'; p++) ttl = ttl*10 + *p - '0';
      if (isspace(*p)) p++;
      }
    else
      break;
    }

  if (!isspace(*p))     /* new domain name */
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
    }                   /* else use previous line's domain name */

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

  if (yield == HOST_NOT_FOUND)
    {
    yield = NO_DATA;
    if (dnssec) *dnssec = TRUE;     /* cancelled by first nonsecure rec found */
    if (aa) *aa = TRUE;             /* cancelled by first non-aa rec found */
    }

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
  if (delay)
    millisleep(delay);

  if (dnssec && !rr_sec)
    *dnssec = FALSE;                    /* cancel AD return */

  if (aa && !rr_aa)
    *aa = FALSE;                        /* cancel AA return */

  if (rr_ignore) continue;

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

  *pk++ = (ttl >>24) & 255;
  *pk++ = (ttl >>16) & 255;
  *pk++ = (ttl >> 8) & 255;
  *pk++ = ttl & 255;

  rdlptr = pk;   /* remember rdlength field */
  pk += 2;

  /* The rest of the data depends on the type */

  switch (tvalue)
    {
    case ns_t_soa:
      p = Ustrtok(p, " ");
      ep = p + Ustrlen(p);
      if (ep[-1] != '.') sprintf(CS ep, "%s.", zone);
      pk = packname(p, pk);                     /* primary ns */
      p = Ustrtok(NULL, " ");
      pk = packname(p , pk);                    /* responsible mailbox */
      *(p += Ustrlen(p)) = ' ';
      while (isspace(*p)) p++;
      pk = longfield(&p, pk);                   /* serial */
      pk = longfield(&p, pk);                   /* refresh */
      pk = longfield(&p, pk);                   /* retry */
      pk = longfield(&p, pk);                   /* expire */
      pk = longfield(&p, pk);                   /* minimum */
      break;

    case ns_t_a:
      inet_pton(AF_INET, CCS p, pk);                /* FIXME: error checking */
      pk += 4;
      break;

    case ns_t_aaaa:
      inet_pton(AF_INET6, CCS p, pk);               /* FIXME: error checking */
      pk += 16;
      break;

    case ns_t_mx:
      pk = shortfield(&p, pk);
      if (ep[-1] != '.') sprintf(CS ep, "%s.", zone);
      pk = packname(p, pk);
      break;

    case ns_t_txt:
      pp = pk++;
      if (*p == '"') p++;   /* Should always be the case */
      while (*p != 0 && *p != '"') *pk++ = *p++;
      *pp = pk - pp - 1;
      break;

    case ns_t_tlsa:
      pk = bytefield(&p, pk);   /* usage */
      pk = bytefield(&p, pk);   /* selector */
      pk = bytefield(&p, pk);   /* match type */
      while (isxdigit(*p))
      {
      value = toupper(*p) - (isdigit(*p) ? '0' : '7') << 4;
      if (isxdigit(*++p))
        {
        value |= toupper(*p) - (isdigit(*p) ? '0' : '7');
        p++;
        }
      *pk++ = value & 255;
      }

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
      if (ep[-1] != '.') sprintf(CS ep, "%s.", zone);
      pk = packname(p, pk);
      break;
    }

  /* Fill in the length, and we are done with this RR */

  rdlptr[0] = ((pk - rdlptr - 2) >> 8) & 255;
  rdlptr[1] = (pk -rdlptr - 2) & 255;
  }

*pkptr = pk;
return (yield == HOST_NOT_FOUND && pass_on_not_found)? PASS_ON : yield;
}


static  void
alarmfn(int sig)
{
}


/*************************************************
*     Special-purpose domains                    *
*************************************************/

static int
special_manyhome(uschar * packet, uschar * domain)
{
uschar *pk = packet + 12;
uschar *rdlptr;
int i, j;

memset(packet, 0, 12);

for (i = 104; i <= 111; i++) for (j = 0; j <= 255; j++)
  {
  pk = packname(domain, pk);
  *pk++ = (ns_t_a >> 8) & 255;
  *pk++ = (ns_t_a) & 255;
  *pk++ = 0;
  *pk++ = 1;     /* class = IN */
  pk += 4;       /* TTL field; don't care */
  rdlptr = pk;   /* remember rdlength field */
  pk += 2;

  *pk++ = 10; *pk++ = 250; *pk++ = i; *pk++ = j;

  rdlptr[0] = ((pk - rdlptr - 2) >> 8) & 255;
  rdlptr[1] = (pk - rdlptr - 2) & 255;
  }

packet[6] = (2048 >> 8) & 255;
packet[7] = 2048 & 255;
packet[10] = 0;
packet[11] = 0;

(void)fwrite(packet, 1, pk - packet, stdout);
return 0;
}

static int
special_again(uschar * packet, uschar * domain)
{
int delay = atoi(CCS domain);  /* digits at the start of the name */
if (delay > 0) sleep(delay);
return TRY_AGAIN;
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
uschar packet[2048 * 32 + 32];
HEADER *header = (HEADER *)packet;
uschar *pk = packet;
BOOL dnssec;
BOOL aa;

signal(SIGALRM, alarmfn);

if (argc != 4)
  {
  fprintf(stderr, "fakens: expected 3 arguments, received %d\n", argc-1);
  return NO_RECOVERY;
  }

/* Find the zones */

(void)sprintf(CS buffer, "%s/dnszones", argv[1]);

d = opendir(CCS buffer);
if (d == NULL)
  {
  fprintf(stderr, "fakens: failed to opendir %s: %s\n", buffer,
    strerror(errno));
  return NO_RECOVERY;
  }

while ((de = readdir(d)) != NULL)
  {
  uschar *name = US de->d_name;
  if (Ustrncmp(name, "qualify.", 8) == 0)
    {
    qualify = fcopystring(US "%s", name + 7);
    continue;
    }
  if (Ustrncmp(name, "db.", 3) != 0) continue;
  if (Ustrncmp(name + 3, "ip4.", 4) == 0)
    zones[zonecount].zone = fcopystring(US "%s.in-addr.arpa", name + 6);
  else if (Ustrncmp(name + 3, "ip6.", 4) == 0)
    zones[zonecount].zone = fcopystring(US "%s.ip6.arpa", name + 6);
  else
    zones[zonecount].zone = fcopystring(US "%s", name + 2);
  zones[zonecount++].zonefile = fcopystring(US "%s", name);
  }
(void)closedir(d);

/* Get the RR type and upper case it, and check that we recognize it. */

Ustrncpy(qtype, argv[3], sizeof(qtype));
qtypelen = Ustrlen(qtype);
for (p = qtype; *p != 0; p++) *p = toupper(*p);

/* Find the domain, lower case it, deal with any specials,
check that it is in a zone that we handle,
and set up the zone file name. The zone names in the table all start with a
dot. */

domlen = Ustrlen(argv[2]);
if (argv[2][domlen-1] == '.') domlen--;
Ustrncpy(domain, argv[2], domlen);
domain[domlen] = 0;
for (i = 0; i < domlen; i++) domain[i] = tolower(domain[i]);

if (Ustrcmp(domain, "manyhome.test.ex") == 0 && Ustrcmp(qtype, "A") == 0)
  return special_manyhome(packet, domain);
else if (domlen >= 14 && Ustrcmp(domain + domlen - 14, "test.again.dns") == 0)
  return special_again(packet, domain);
else if (domlen >= 13 && Ustrcmp(domain + domlen - 13, "test.fail.dns") == 0)
  return NO_RECOVERY;


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

(void)sprintf(CS buffer, "%s/dnszones/%s", argv[1], zonefile);

/* Initialize the start of the response packet. We don't have to fake up
everything, because we know that Exim will look only at the answer and
additional section parts. */

memset(packet, 0, 12);
pk += 12;

/* Open the zone file. */

f = fopen(CS buffer, "r");
if (f == NULL)
  {
  fprintf(stderr, "fakens: failed to open %s: %s\n", buffer, strerror(errno));
  return NO_RECOVERY;
  }

/* Find the records we want, and add them to the result. */

count = 0;
yield = find_records(f, zone, domain, qtype, qtypelen, &pk, &count, &dnssec, &aa);
if (yield == NO_RECOVERY) goto END_OFF;
header->ancount = htons(count);

/* If the AA bit should be set (as indicated by the AA prefix in the zone file),
we are expected to return some records in the authoritative section. Bind9: If
there is data in the answer section, the authoritative section contains the NS
records, otherwise it contains the SOA record.  Currently we mimic this
behaviour for the first case (there is some answer record).
*/

if (aa)
  find_records(f, zone, zone[0] == '.' ? zone+1 : zone, US"NS", 2, &pk, &count, NULL, NULL);
header->nscount = htons(count - ntohs(header->ancount));

/* There is no need to return any additional records because Exim no longer
(from release 4.61) makes any use of them. */
header->arcount = 0;

if (dnssec)
  header->ad = 1;

if (aa)
  header->aa = 1;

/* Close the zone file, write the result, and return. */

END_OFF:
(void)fclose(f);
(void)fwrite(packet, 1, pk - packet, stdout);
return yield;
}

/* vi: aw ai sw=2 sts=2 ts=8 et
*/
/* End of fakens.c */
