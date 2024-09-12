# Exim filter

if foranyaddress $h_to: ($thisaddress contains usery) then
  headers add "Found: yes\nFound2: yes"
else
  headers add "Found: no"
endif      
