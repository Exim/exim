# Exim filter

if foranyaddress $h_to: ($thisaddress contains abcd) then
  headers add "Found: abcd yes"
else
  headers add "Found: abcd no"
endif      

if foranyaddress $h_to: ($thisaddress contains xyz) then
  headers add "Found: xyz yes"
else
  headers add "Found: xyz no"
endif      

headers add "TO: >$h_to:<"


