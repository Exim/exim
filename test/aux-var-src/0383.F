# Exim filter (system filter for test 0383)

if error_message then finish endif

if foranyaddress $h_to: ($thisaddress matches "^(alice)") then
  pipe "DIR/aux-fixed/showenv \"${if match_address {$thisaddress}{alice@test.ex}{$value}}\" \"${if inlist {$1}{alice} {$value}}\""
  finish
endif   

if foranyaddress $h_to: ($thisaddress matches "^(marny)") then
  pipe "DIR/aux-fixed/showenv $thisaddress $1"
  finish
endif   

if $h_to: matches "^(j..)" then
  pipe "DIR/aux-fixed/showenv \"${if inlist {$1}{jab} {$value}}\""
endif   

