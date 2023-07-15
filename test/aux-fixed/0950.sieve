# Sieve filter
#

require "fileinto";

if header :contains "from" "coyote" {
	  discard;
} elsif header :contains "from" "spot_this" {
	  fileinto "myfolder";
} elsif header :contains "from" "redirect" {
	  redirect "fred@some_other_dom.ain";
}
