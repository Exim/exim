# Exim filter (user filter for test 444)

if error_message then finish endif

if foranyaddress $h_to: ($thisaddress matches "^(...)") then
  pipe "DIR/aux-fixed/showenv $thisaddress $1"
endif   

