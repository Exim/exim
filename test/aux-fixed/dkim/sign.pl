use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;  #recommended
use Getopt::Long;

# default option values
my $method = "simple/simple";
my $selector = "sel";
my $keyfile = "aux-fixed/dkim/dkim.private";
my $algorithm = "rsa-sha1";

GetOptions(
	"method=s" => \$method,
	"selector=s" => \$selector,
	"keyfile=s" => \$keyfile,
	"algorithm=s" => \$algorithm,
);

# create a signer object
my $dkim = Mail::DKIM::Signer->new(
                  Algorithm => $algorithm,
                  Method => $method,
                  Domain => "test.ex",
                  Selector => $selector,
                  KeyFile => $keyfile,
             );

# read an email and pass it into the signer, one line at a time
while (<STDIN>)
{
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;

# what is the signature result?
my $signature = $dkim->signature;
print $signature->as_string;
print "\n";

#print $dkim->headers;
#print "\n";
