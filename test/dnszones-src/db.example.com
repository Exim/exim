; This is a testing zone file for use when testing DNS handling in Exim. This
; is a fake zone of no real use - hence no SOA record. The zone name is
; example.com. This file is passed through the substitution mechanism before being
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

; really short neg-cache interval, for testing NXDOMAIN caching
example.com.     SOA     exim.test.ex. hostmaster.exim.test.ex 1430683638 1200 120 604800 2

example.com.     NS      exim.example.com.

; The real example.com has an SPF record; duplicate that here

example.com.	TXT     v=spf1 -all

double		TXT	v=spf1 include:_spf.google.com ~all
		TXT	v=spf1 +a +mx -all

doubleplus	TXT	v=spf1 include:_spf.google.com ~all
		TXT	google-site-verification=q-4MSVLjluQIsBztu5jzJBxAcJXzNcHAk0jHTZEamB8
		TXT	v=spf1 +a +mx -all

uppercase	TXT	v=sPf1 +all
passme.helo	TXT	v=spf1 +all

; Alias A record for the local host, under the name "server1"

server1               A     HOSTIPV4
serverbadname         A     HOSTIPV4
serverchain1	      CNAME server1
alternatename.server1 CNAME server1

; DANE testing

; a broken dane config where the name does not match in the cert, TA-mode, dane-requested
; NOTE: the server uses the example.net cert hence the mismatch
;
; TLSA_AUTOGEN
; openssl x509 -in aux-fixed/exim-ca/example.net/CA/CA.pem -fingerprint -sha256 -noout \
;  | awk -F= '{print $2}' | tr -d : | tr '[A-F]' '[a-f]'
;
;
DNSSEC danebroken7  A       127.0.0.1
DNSSEC _1225._tcp.danebroken7 TLSA 2 0 1 68932e8eed228ff72a53c832aed4db07cecb099fe8bdf48952237f20724a1ab4

; the same, EE-mode
;
; TLSA_AUTOGEN
; openssl x509 -in aux-fixed/exim-ca/example.net/server1.example.net/server1.example.net.pem -noout -pubkey \
; | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $2}'
;
DNSSEC danebroken8  A       127.0.0.1
DNSSEC _1225._tcp.danebroken8 TLSA 3 1 1 61e0bb2042c975bc018a47b5961ac1ce8e84f162f2147e97f56736177bb8fc8e

; End
