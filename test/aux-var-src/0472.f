# Exim filter

deliver userz$sn1

logfile DIR/test-stderr

logwrite "------- $local_part filter -----------------"
logwrite "sn0=$sn0 sn1=$sn1 sn2=$sn2 sn3=$sn3 sn4=$sn4"
logwrite "sn5=$sn5 sn6=$sn6 sn7=$sn7 sn8=$sn8 sn9=$sn9"

# End
