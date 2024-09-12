# The map/match here detaints the $recipients
#
if $recipients contains pipe then
  pipe "DIR/aux-fixed/showenv \
    \"${map {<, $recipients} \
        {${if match_address {$item} {pipe@test.ex : another@test.ex : a-third@test.ex} {$value}}}}\""
endif   

