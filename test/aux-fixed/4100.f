# Exim filter

testprint "subject = >$h_subject:<"
testprint "raw subject = >$rh_subject:<"
testprint "to = >$h_to:<"
testprint "raw to = >$rheader_to:<"

testprint "rX-8: >$rh_X-8:<"
testprint "bX-8: >$bh_X-8:<"
testprint " X-8: >$h_X-8:<"

testprint "rX-9: >$rh_X-9:<"
testprint "bX-9: >$bh_X-9:<"
testprint " X-9: >$h_X-9:<"

testprint "rX-10: >$rh_X-10:<"
testprint "bX-10: >$bh_X-10:<"
testprint " X-10: >$h_X-10:<"

headers charset "UTF-8"
testprint " X-8: >$h_X-8:<"
testprint " X-9: >$h_X-9:<"
testprint " X-10: >$h_X-10:<"

headers charset "ISO-8859-1//IGNORE"
testprint " X-8: >$h_X-8:<"

