use Mail::DKIM::ARC::Signer;
use Mail::DKIM::TextWrap;  #recommended
use Getopt::Long;

# default option values
my $method = "simple/simple";
my $selector = "sel";
my $keyfile = "aux-fixed/dkim/dkim.private";
my $algorithm = "rsa-sha256";

GetOptions(
	"method=s" => \$method,
	"selector=s" => \$selector,
	"keyfile=s" => \$keyfile,
	"algorithm=s" => \$algorithm,
);

# create a signer object
my $signer = Mail::DKIM::ARC::Signer->new(
                  Algorithm => $algorithm,
                  Chain => 'none',    # or pass|fail|ar
                  Domain => 'test.ex',
                  SrvId => 'test.ex',
                  Selector => $selector,
                  KeyFile => $keyfile,
                  Headers => 'x-header:x-header2',
             );


  # NOTE: any email being ARC signed must have an Authentication-Results
  # header so that the ARC seal can cover those results copied into
  # an ARC-Authentication-Results header.

# read an email and pass it into the signer, one line at a time
while (<STDIN>)
{
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $signer->PRINT("$_\015\012");
}
$signer->CLOSE;

die 'Failed' . $signer->result_details() unless $signer->result() eq 'sealed';

# Get all the signature headers to prepend to the message
# ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results
# in that order.
print $signer->as_string;
