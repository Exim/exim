; This is a testing zone file for use when testing DNS handling in Exim. This
; is a fake zone of no real use. The zone name is
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
;
; Several prefixes may be used, see the source in src/fakens.c for a complete list
; and description.

test.ex.     NS      exim.test.ex.
test.ex.     SOA     exim.test.ex. hostmaster.exim.test.ex 1430683638 1200 120 604800 3600

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

; A host with punycoded UTF-8 characters used for its lookup ( mx.π.test.ex )

mx.xn--1xa         A       V4NET.255.255.255

; A non-standard name for localhost

thishost     A       127.0.0.1
localhost4   A       127.0.0.1

; A localhost with short TTL

TTL=2 shorthost A    127.0.0.1


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

eximtesthost     A       HOSTIPV4
alias-eximtesthost CNAME eximtesthost.test.ex.

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

; a CNAME pointing to a name with both ipv4 and ipv6 A-records
; and one with only ipv4

cname46      CNAME   localhost
cname4       CNAME   thishost

; -------- Testing RBL records -------

; V4NET.11.12.13 is deliberately not reverse-registered

13.12.11.V4NET.rbl    A   127.0.0.2
                      TXT "This is a test blacklisting message"
TTL=2 14.12.11.V4NET.rbl A 127.0.0.2
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

; MX with punycoded UTF-8 characters used for its lookup ( π.test.ex )

xn--1xa      MX  0  mx.π.test.ex.

; MX with actual UTF-8 characters in its name, for allow_utf8_domains mode test

π            MX  0  mx.xn--1xa.test.ex.

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

; ------- Testing DNSSEC ----------

mx-unsec-a-unsec        MX 5 a-unsec
mx-unsec-a-sec          MX 5 a-sec
DNSSEC mx-sec-a-unsec   MX 5 a-unsec
DNSSEC mx-sec-a-sec     MX 5 a-sec
DNSSEC mx-sec-a-aa      MX 5 a-aa
AA mx-aa-a-sec          MX 5 a-sec

a-unsec        A V4NET.0.0.100
DNSSEC a-sec   A V4NET.0.0.100
DNSSEC l-sec   A 127.0.0.1

AA a-aa        A V4NET.0.0.100

; ------- Testing DANE ------------
; Since these refer to certs in the exim-ca tree, they must be regenerated any time that tree is.
;

; full suite dns chain, sha512
;
; openssl x509 -in aux-fixed/exim-ca/example.com/server1.example.com/server1.example.com.pem -noout -pubkey \
; | openssl pkey -pubin -outform DER \
; | openssl dgst -sha512 \
; | awk '{print $2}'
;
DNSSEC mxdane512ee          MX  1  dane512ee
DNSSEC dane512ee            A      HOSTIPV4
DNSSEC _1225._tcp.dane512ee TLSA  3 1 2 69e8a5ddf24df2c51dc503959d26e621be4ce3853f71890512de3ae3390c5749ef3368dd4d274669b0653da8c3663f12ca092cd98e5e242e4de57ee6aa01cde1

; A-only, sha256
;
; openssl x509 -in aux-fixed/exim-ca/example.com/server1.example.com/server1.example.com.pem -noout -pubkey \
; | openssl pkey -pubin -outform DER \
; | openssl dgst -sha256 \
; | awk '{print $2}'
;
DNSSEC dane256ee            A      HOSTIPV4
DNSSEC _1225._tcp.dane256ee TLSA  3 1 1 827664533176a58b3578e0e91d77d79d036d3a97f023d82baeefa8b8e13b44f8

; full MX, sha256, TA-mode
;
; openssl x509 -in aux-fixed/exim-ca/example.com/CA/CA.pem -fingerprint -sha256 -noout \
; | awk -F= '{print $2}' | tr -d : | tr '[A-F]' '[a-f]'
;
DNSSEC mxdane256ta          MX  1  dane256ta
DNSSEC dane256ta            A      HOSTIPV4
DNSSEC _1225._tcp.dane256ta TLSA 2 0 1 cb0fa6a633e52c787657f5ca0da1030800223cac459577b9b6a55ac9733348e5


; full MX, sha256, TA-mode, cert-key-only
; Indicates a trust-anchor for a chain involving an Authority Key ID extension
; linkage, as this excites a bug in OpenSSL 1.0.2 which the DANE code has to
; work around, while synthesizing a selfsigned parent for it.
; As it happens it is also an intermediate cert in the CA-rooted chain, as this
; was initially thought ot be a factor.
;
; openssl x509 -in aux-fixed/exim-ca/example.com/CA/Signer.pem -noout -pubkey \
; | openssl pkey -pubin -outform DER \
; | openssl dgst -sha256 \
; | awk '{print $2}'
;
DNSSEC mxdane256tak          MX  1  dane256tak
DNSSEC dane256tak            A      HOSTIPV4
DNSSEC _1225._tcp.dane256tak TLSA 2 1 1 73e279c0f5f5a9ee9851bbbc39023603d7b266acfd0764419c3b07cc380b79f9


; A multiple-return MX where all TLSA lookups defer
DNSSEC mxdanelazy           MX  1   danelazy
DNSSEC                      MX  2   danelazy2

DNSSEC danelazy             A       HOSTIPV4
DNSSEC danelazy2            A       127.0.0.1

DNSSEC _1225._tcp.danelazy  CNAME   test.again.dns.
DNSSEC _1225._tcp.danelazy2 CNAME   test.again.dns.

; hosts with no TLSA (just missing here, hence the TLSA NXDMAIN is _insecure_; a broken dane config)
; 1 for dane-required, 2 for merely requested
DNSSEC dane.no.1            A       HOSTIPV4
DNSSEC dane.no.2            A       127.0.0.1

; a broken dane config (or under attack) where the TLSA lookup fails (as opposed to there not being one)
DNSSEC danebroken1          A       127.0.0.1
_1225._tcp.danebroken1      CNAME   test.fail.dns.

; a broken dane config (or under attack) where the TLSA record is wrong
; (127.0.0.1 for merely dane-requested, but having gotten the TLSA it is supposedly definitive)
DNSSEC danebroken2          A       127.0.0.1
DNSSEC _1225._tcp.danebroken2 TLSA 2 0 1 cb0fa60000000000000000000000000000000000000000000000000000000000

; a broken dane config (or under attack) where the TLSA record is correct but not DNSSEC-assured
; (record copied from dane256ee above)
; 3 for dane-requested, 4 for dane-required
DNSSEC danebroken3          A       127.0.0.1
_1225._tcp.danebroken3 TLSA 2 0 1 827664533176a58b3578e0e91d77d79d036d3a97f023d82baeefa8b8e13b44f8
DNSSEC danebroken4          A       HOSTIPV4
_1225._tcp.danebroken4 TLSA 2 0 1 827664533176a58b3578e0e91d77d79d036d3a97f023d82baeefa8b8e13b44f8

; a broken dane config (or under attack) where the address record is correct but not DNSSEC-assured
; (TLSA record copied from dane256ee above)
; 5 for dane-requested, 6 for dane-required
danebroken5          A       127.0.0.1
DNSSEC _1225._tcp.danebroken5 TLSA 2 0 1 827664533176a58b3578e0e91d77d79d036d3a97f023d82baeefa8b8e13b44f8
danebroken6          A       HOSTIPV4
DNSSEC _1225._tcp.danebroken6 TLSA 2 0 1 827664533176a58b3578e0e91d77d79d036d3a97f023d82baeefa8b8e13b44f8

; a good dns config saying there is no dane support, by securely returning NOXDOMAIN for TLSA lookups
; 3 for dane-required, 4 for merely requested
; the TLSA data here is dummy; ignored
DNSSEC dane.no.3            A       HOSTIPV4
DNSSEC dane.no.4            A       127.0.0.1

DNSSEC NXDOMAIN _1225._tcp.dane.no.3 TLSA 2 0 1 eec923139018c540a344c5191660ecba1ac3708525a98bfc338e17f31d3fa741
DNSSEC NXDOMAIN _1225._tcp.dane.no.4 TLSA 2 0 1 eec923139018c540a344c5191660ecba1ac3708525a98bfc338e17f31d3fa741

; a mixed-usage set of TLSA records, EE one failing.  TA one coped from dane256ta.
DNSSEC danemixed            A      127.0.0.1
DNSSEC _1225._tcp.danemixed TLSA  2 0 1 cb0fa6a633e52c787657f5ca0da1030800223cac459577b9b6a55ac9733348e5
DNSSEC                      TLSA  3 1 1 8276000000000000000000000000000000000000000000000000000000000000

; ------- Testing delays ------------

DELAY=500 delay500   A HOSTIPV4
DELAY=1500 delay1500 A HOSTIPV4

; ------- DKIM ---------

; public key, base64 - matches private key in aux-fixed/dkim/dkim.private
;  openssl genrsa -out aux-fixed/dkim/dkim.private 1024
;  openssl rsa -in aux-fixed/dkim/dkim.private -out /dev/stdout -pubout -outform PEM
;
; Deliberate bad version, having extra backslashes
; sha256-hash-only version.... appears to be too long, gets truncated
;
; Another, 512-bit (with a Notes field)
; 512 requiring sha1 hash
; 512 requiring sha256 hash
;
sel._domainkey TXT "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXRFf+VhT+lCgFhhSkinZKcFNeRzjYdW8vT29Rbb3NadvTFwAd+cVLPFwZL8H5tUD/7JbUPqNTCPxmpgIL+V5T4tEZMorHatvvUM2qfcpQ45IfsZ+YdhbIiAslHCpy4xNxIR3zylgqRUF4+Dtsaqy3a5LhwMiKCLrnzhXk1F1hxwIDAQAB"
sel_bad._domainkey TXT "v=DKIM1\; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXRFf+VhT+lCgFhhSkinZKcFNeRzjYdW8vT29Rbb3NadvTFwAd+cVLPFwZL8H5tUD/7JbUPqNTCPxmpgIL+V5T4tEZMorHatvvUM2qfcpQ45IfsZ+YdhbIiAslHCpy4xNxIR3zylgqRUF4+Dtsaqy3a5LhwMiKCLrnzhXk1F1hxwIDAQAB"
sel_sha256._domainkey TXT "v=DKIM1; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXRFf+VhT+lCgFhhSkinZKcFNeRzjYdW8vT29Rbb3NadvTFwAd+cVLPFwZL8H5tUD/7JbUPqNTCPxmpgIL+V5T4tEZMorHatvvUM2qfcpQ45IfsZ+YdhbIiAslHCpy4xNxIR3zylgqRUF4+Dtsaqy3a5LhwMiKCLrnzhXk1F1hxwIDAQAB"

ses._domainkey TXT "v=DKIM1; n=halfkilo; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6eAQxd9didJ0/+05iDwJOqT6ly826Vi8aGPecsBiYK5/tAT97fxXk+dPWMZp9kQxtknEzYjYjAydzf+HQ2yJMCAwEAAQ=="
ses_sha1._domainkey TXT "v=DKIM1; h=sha1; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6eAQxd9didJ0/+05iDwJOqT6ly826Vi8aGPecsBiYK5/tAT97fxXk+dPWMZp9kQxtknEzYjYjAydzf+HQ2yJMCAwEAAQ=="
ses_sha256._domainkey TXT "v=DKIM1; h=sha256; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6eAQxd9didJ0/+05iDwJOqT6ly826Vi8aGPecsBiYK5/tAT97fxXk+dPWMZp9kQxtknEzYjYjAydzf+HQ2yJMCAwEAAQ=="

sel2._domainkey TXT "v=spf1 mx a include:spf.nl2go.com -all"
sel2._domainkey TXT "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXRFf+VhT+lCgFhhSkinZKcFNeRzjYdW8vT29Rbb3NadvTFwAd+cVLPFwZL8H5tUD/7JbUPqNTCPxmpgIL+V5T4tEZMorHatvvUM2qfcpQ45IfsZ+YdhbIiAslHCpy4xNxIR3zylgqRUF4+Dtsaqy3a5LhwMiKCLrnzhXk1F1hxwIDAQAB"

; EC signing, using Ed25519
; - needs GnuTLS 3.6.0 (fedora rawhide has that)
;           certtool --generate-privkey --key-type=ed25519 --outfile=dkim_ed25519.private
;	    certtool --load_privkey=dkim_ed25519.private --pubkey_info --outder | tail -c +13 | base64

sed._domainkey TXT "v=DKIM1; k=ed25519; p=sPs07Vu29FpHT/80UXUcYHFOHifD4o2ZlP2+XUh9g6E="

; version of the above wrapped in SubjectPublicKeyInfo, in case the WG plumps in that direction
;	certtool --load_privkey=aux-fixed/dkim/dkim_ed25519.private --pubkey_info
;	 (and grab the b64 content from between the pem headers)

sedw._domainkey TXT "v=DKIM1; k=ed25519; p=MCowBQYDK2VwAyEAsPs07Vu29FpHT/80UXUcYHFOHifD4o2ZlP2+XUh9g6E="


; End
