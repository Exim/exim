; This is a testing zone file for use when testing DNS handling in Exim. This
; is a fake zone of no real use - hence no SOA record. The zone name is
; test.ex. This file is passed through the substitution mechanism before being
; used by the fakens auxiliary program. This inserts the actual IP addresses
; of the local host into the zone.

; NOTE (1): apart from ::1, IPv6 addresses must always have 8 components. Do
; not abbreviate them by using the :: feature. Leading zeros in components may,
; however, be omitted.

; NOTE (2): the fakens program is very simple and assumes that the buffer into
; which is puts the response is always going to be big enough. In other words,
; the expectation is for just a few RRs for each query.

; NOTE (3): the top-level networks for testing addresses are parameterized by
; the use of V4NET and V6NET. These networks should be such that no real
; host ever uses them.

test.ex.     NS      exim.test.ex.

test.ex.     TXT     "A TXT record for test.ex."
s/lash       TXT     "A TXT record for s/lash.test.ex."

cname        CNAME   test.ex.

ptr          PTR     data.for.ptr.test.ex.

; Standard localhost handling

localhost    A       127.0.0.1
localhost    AAAA    ::1

; This name exists only if qualified; it is never automatically qualified

dontqualify  A       V4NET.255.255.254

; A host with upper case letters in its canonical name

UpperCase    A       127.0.0.1

; A host with UTF-8 characters in its name

mx.π        A       V4NET.255.255.255

; A non-standard name for localhost

thishost     A       127.0.0.1

; Something that gives both the IP and the loopback

thisloop     A       HOSTIPV4
             A       127.0.0.1

; Something that gives an unreachable IP and the loopback

badloop      A       V4NET.0.0.1
             A       127.0.0.1

; Another host with both A and AAAA records

46           A       V4NET.0.0.4
             AAAA    V6NET:ffff:836f:0a00:000a:0800:200a:c031

; And another

46b          A       V4NET.0.0.5
             AAAA    V6NET:ffff:836f:0a00:000a:0800:200a:c033

; A working IPv4 address and a non-working IPv6 address, with different
; names so they can have different MX values

46c          AAAA    V6NET:ffff:836f:0a00:000a:0800:200a:c033
46d          A       HOSTIPV4

; A host with just a non-local IPv6 address

v6           AAAA    V6NET:ffff:836f:0a00:000a:0800:200a:c032

; Alias A and CNAME records for the local host, under the name "eximtesthost"
; Make the A covered by DNSSEC and add a TLSA for it.

DNSSEC eximtesthost     A       HOSTIPV4
alias-eximtesthost CNAME eximtesthost.test.ex.

DNSSEC _1225._tcp.eximtesthost	TLSA	3 1 2 f000baaa

; A bad CNAME

badcname     CNAME   rhubarb.test.ex.

; Test a name containing an underscore

a_b          A       99.99.99.99

; The reverse registration for this name is an empty string

empty        A       V4NET.255.255.255

; Some IPv6 stuff

eximtesthost.ipv6 AAAA   HOSTIPV6
test2.ipv6   AAAA    V6NET:2101:12:1:a00:20ff:fe86:a062
test3.ipv6   AAAA    V6NET:1234:5:6:7:8:abc:0d

; A case of forward and backward pointers disagreeing

badA         A       V4NET.99.99.99
badB         A       V4NET.99.99.98

; A host with multiple names in different (sub) domains
; These are intended to be within test.ex - absence of final dots is deliberate

x.gov.uk     A       V4NET.99.99.97
x.co.uk      A       V4NET.99.99.97

; A host, the reverse lookup of whose IP address gives this name plus another
; that does not forward resolve to the same address

oneback      A       V4NET.99.99.90
host1.masq   A       V4NET.90.90.90

; Fake hosts are registered in the V4NET.0.0.0 subnet. In the past, the
; 10.0.0.0/8 network was used; hence the names of the hosts.

ten-1        A       V4NET.0.0.1
ten-2        A       V4NET.0.0.2
ten-3        A       V4NET.0.0.3
ten-3-alias  A       V4NET.0.0.3
ten-3xtra    A       V4NET.0.0.3
ten-4        A       V4NET.0.0.4
ten-5        A       V4NET.0.0.5
ten-6        A       V4NET.0.0.6
ten-5-6      A       V4NET.0.0.5
             A       V4NET.0.0.6

ten-99       A       V4NET.0.0.99

black-1      A       V4NET.11.12.13
black-2      A       V4NET.11.12.14

myhost       A       V4NET.10.10.10
myhost2      A       V4NET.10.10.10

other1       A       V4NET.12.4.5
other2       A       V4NET.12.3.1
             A       V4NET.12.3.2

other99      A       V4NET.99.0.1

testsub.sub  A       V4NET.99.0.3

; This one's real name really is recurse.test.ex.test.ex. It is done like
; this for testing host widening, without getting tangled up in qualify issues.

recurse.test.ex   A  V4NET.99.0.2

; -------- Testing RBL records -------

; V4NET.11.12.13 is deliberately not reverse-registered

13.12.11.V4NET.rbl    A   127.0.0.2
                      TXT "This is a test blacklisting message"
14.12.11.V4NET.rbl    A   127.0.0.2
                      TXT "This is a test blacklisting message"
15.12.11.V4NET.rbl    A   127.0.0.2
                      TXT "This is a very long blacklisting message, continuing for ages and ages and certainly being longer than 128 characters which was a previous limit on the length that Exim was prepared to handle."

14.12.11.V4NET.rbl2   A   127.0.0.2
                      TXT "This is a test blacklisting2 message"
16.12.11.V4NET.rbl2   A   127.0.0.2
                      TXT "This is a test blacklisting2 message"

14.12.11.V4NET.rbl3   A   127.0.0.2
                      TXT "This is a test blacklisting3 message"
15.12.11.V4NET.rbl3   A   127.0.0.3
                      TXT "This is a very long blacklisting message, continuing for ages and ages and certainly being longer than 128 characters which was a previous limit on the length that Exim was prepared to handle."

20.12.11.V4NET.rbl4   A   127.0.0.6
21.12.11.V4NET.rbl4   A   127.0.0.7
22.12.11.V4NET.rbl4   A   127.0.0.128
                      TXT "This is a test blacklisting4 message"

22.12.11.V4NET.rbl5   A   127.0.0.1
                      TXT "This is a test blacklisting5 message"

1.13.13.V4NET.rbl     CNAME non-exist.test.ex.
2.13.13.V4NET.rbl     A   127.0.0.1
                      A   127.0.0.2

; -------- Testing MX records --------

DNSSEC mxplain      MX  1  eximtesthost.

mxcased      MX  5  ten-99.TEST.EX.

; Points to a host with both A and AAAA

mx46         MX  46 46.test.ex.

; Points to two hosts with both kinds of address, equal precedence

mx4646       MX  46 46.test.ex.
             MX  46 46b.test.ex.

; Ditto, with a third IPv6 host

mx46466      MX  46 46.test.ex.
             MX  46 46b.test.ex.
             MX  46 v6.test.ex.

; This time, change precedence

mx46466b     MX  46 46.test.ex.
             MX  47 46b.test.ex.
             MX  48 v6.test.ex.

; Points to a host with a working IPv4 and a non-working IPv6 record

mx46cd       MX  10 46c.test.ex.
             MX  11 46d.test.ex.

; Two equal precedence pointing to a v4 and a v6 host

mx246        MX  10 v6.test.ex.
             MX  10 ten-1.test.ex.

; Lowest-numbered points to local host

mxt1         MX  5  eximtesthost.test.ex.

; Points only to non-existent hosts

mxt2         MX  5  not-exist.test.ex.

; Points to some non-existent hosts;
; Lowest numbered existing points to local host

mxt3         MX  5  not-exist.test.ex.
             MX  6  eximtesthost.test.ex.

; Points to some non-existent hosts;
; Lowest numbered existing points to non-local host

mxt3r        MX  5  not-exist.test.ex.
             MX  6  exim.org.

; Points to an alias

mxt4         MX  5  alias-eximtesthost.test.ex.

; Various combinations of precedence and local host

mxt5         MX  5  eximtesthost.test.ex.
             MX  5  ten-1.test.ex.

mxt6         MX  5  ten-1.test.ex.
             MX  6  eximtesthost.test.ex.
             MX  6  ten-2.test.ex.

mxt7         MX  5  ten-2.test.ex.
             MX  6  ten-3.test.ex.
             MX  7  eximtesthost.test.ex.
             MX  8  ten-1.test.ex.

mxt8         MX  5  ten-2.test.ex.
             MX  6  ten-3.test.ex.
             MX  7  eximtesthost.test.ex.
             MX  7  ten-4.test.ex.
             MX  8  ten-1.test.ex.

; Same host appearing twice; make some variants in different orders to
; simulate a real nameserver and its round robinning

mxt9         MX  5  ten-1.test.ex.
             MX  6  ten-2.test.ex.
             MX  7  ten-3.test.ex.
             MX  8  ten-1.test.ex.

mxt9a        MX  6  ten-2.test.ex.
             MX  7  ten-3.test.ex.
             MX  8  ten-1.test.ex.
             MX  5  ten-1.test.ex.

mxt9b        MX  7  ten-3.test.ex.
             MX  8  ten-1.test.ex.
             MX  5  ten-1.test.ex.
             MX  6  ten-2.test.ex.

; MX pointing to IP address

mxt10        MX  5  V4NET.0.0.1.

; Several MXs pointing to local host

mxt11        MX  5  localhost.test.ex.
             MX  6  localhost.test.ex.

mxt11a       MX  5  localhost.test.ex.
             MX  6  ten-1.test.ex.

mxt12        MX  5  local1.test.ex.
             MX  6  local2.test.ex.

local1       A   127.0.0.2
local2       A   127.0.0.2

; Some more

mxt13        MX  4  other1.test.ex.
             MX  5  other2.test.ex.

; Different hosts with same IP addresses in the list

mxt14        MX  4  ten-5-6.test.ex.
             MX  5  ten-5.test.ex.
             MX  6  ten-6.test.ex.

; Non-local hosts with different precedence

mxt15        MX 10  ten-1.test.ex.
             MX 20  ten-2.test.ex.

; Large number of IP addresses at one MX value, and then some
; at another, to check that hosts_max_try tries the MX different
; values if it can.

mxt99        MX  1  ten-1.test.ex.
             MX  1  ten-2.test.ex.
             MX  1  ten-3.test.ex.
             MX  1  ten-4.test.ex.
             MX  1  ten-5.test.ex.
             MX  1  ten-6.test.ex.
             MX  3  black-1.test.ex.
             MX  3  black-2.test.ex.

; Special case test for @mx_any (to doublecheck a reported Exim 3 bug isn't
; in Exim 4). The MX points to two names, each with multiple addresses. The
; very last address is the local host. When Exim is testing, it will sort
; these addresses into ascending order.

mxt98        MX  1  98-1.test.ex.
             MX  2  98-2.test.ex.

98-1         A   V4NET.1.2.3
             A   V4NET.4.5.6

98-2         A   V4NET.7.8.9
             A   HOSTIPV4

; IP addresses with the same MX value

mxt97        MX  1  ten-1.test.ex.
             MX  1  ten-2.test.ex.
             MX  1  ten-3.test.ex.
             MX  1  ten-4.test.ex.

; MX pointing to a single-component name that exists if qualified, but not
; if not. We use the special name dontqualify to stop the fake resolver
; qualifying it.

mxt1c        MX  1  dontqualify.

; MX with UTF-8 characters in its name

π           MX  0  mx.π.test.ex.

; -------- Testing SRV records --------

_smtp._tcp.srv01    SRV  0 0 25 ten-1.test.ex.

_smtp._tcp.srv02    SRV  1 3 99 ten-1.test.ex.
                    SRV  1 1 99 ten-2.test.ex.
                    SRV  3 0 66 ten-3.test.ex.

_smtp._tcp.nosmtp   SRV  0 0 0  .

_smtp2._tcp.srv03   SRV  0 0 88 ten-4.test.ex.

_smtp._tcp.srv27    SRV  0 0 PORT_S localhost


; -------- With some for CSA testing plus their A records -------

_client._smtp.csa1  SRV  1 2 0  csa1.test.ex.
_client._smtp.csa2  SRV  1 1 0  csa2.test.ex.

csa1         A   V4NET.9.8.7
csa2         A   V4NET.9.8.8

; End
