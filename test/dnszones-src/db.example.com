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

example.com.     NS      exim.example.com.

; Alias A record for the local host, under the name "server1"

server1     A       HOSTIPV4

; DANE testing

; a broken dane config where the name does not match in the cert, TA-mode, dane-requested
; NOTE: the server uses the example.net cert hence the mismatch
;
; openssl x509 -in aux-fixed/exim-ca/example.net/CA/CA.pem -fingerprint -sha256 -noout \
;  | awk -F= '{print $2}' | tr -d : | tr '[A-F]' '[a-f]'
;
;
DNSSEC danebroken7  A       127.0.0.1
DNSSEC _1225._tcp.danebroken7 TLSA 2 0 1 13646cc92c038932f57f752559271b893045eda39f765fc8369b05b2b9c3ac88

; the same, EE-mode
;
; openssl x509 -in aux-fixed/exim-ca/example.net/server1.example.net/server1.example.net.pem -noout -pubkey \
; | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $2}'
;
DNSSEC danebroken8  A       127.0.0.1
DNSSEC _1225._tcp.danebroken8 TLSA 3 1 1 3cc2a6efabd847663b92f827681fd8612fd4d001ea85057d79ea541fb2de02ac

; End
