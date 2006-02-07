# Exim filter

if "${if def:h_test-headers:{yes}{no}}" is yes then
  testprint ------------------------------------------------
  testprint $message_headers
  testprint ------------------------------------------------
  headers remove test-headers:more-test-headers
  headers add "added-header: this is added\nadded-header2: a second line"    
  testprint $message_headers
  testprint ------------------------------------------------
endif

if $recipients matches deliverfromfilter then
  deliver dff@test.ex
  finish
endif    

testprint "message_size      = $message_size"
testprint "message_body_size = $message_body_size"
testprint "body_linecount    = $body_linecount"
testprint "message_body      = $message_body"
testprint "message_body_end  = $message_body_end"

logfile DIR/spool/log/mainlog

if first_delivery then
  logwrite "$tod_log $message_id \"$h_subject:\" first delivery\n"
else   
  logwrite "$tod_log $message_id \"$h_subject:\" not first delivery\n"
endif

if error_message then finish endif

headers add "X-added: qualify_domain is $qualify_domain"
headers remove remove-this

if $recipients does not match filter then
  unseen deliver userz@$qualify_domain errors_to abcd@$qualify_domain
endif   

if $h_subject contains "fail this" then 
  fail text "subject was\t\"$h_subject:\" (filter fail)"
endif   

if $h_subject contains "defer this" then 
  defer text "subject was\t\"$h_subject:\" (filter defer)"
endif   

if $h_subject contains "freeze this" then 
  freeze "subject was \"$h_subject:\"\nHere are two extra\nlines of text"
else   

if $h_subject matches ^reply then
  mail to $return_path
  subject "An auto reply: qualify_domain=$qualify_domain"
  text "This is a text line"
endif
endif
