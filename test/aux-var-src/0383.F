# Exim filter (system filter for test 444)

if error_message then finish endif

if foranyaddress $h_to: ($thisaddress matches "^(alice)") then
  pipe "DIR/aux-fixed/showenv $thisaddress $1"
  finish
endif   

if $h_to: matches "^(j..)" then
  pipe "DIR/aux-fixed/showenv $1"
endif   

