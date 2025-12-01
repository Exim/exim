use POSIX qw(locale_h);
use Net::DNS::Resolver;

sub foo { "Subroutine foo called with args: @_" }

sub foo_undef { undef }

sub foo_die { die 'expiring...' }

sub readvar { Exim::expand_string("\$$_[0]") }

sub return_scalar { 42 }

sub return_list { (10, 20, 30) }

sub return_variable_vector { @x = (4, 5, 6) }

sub return_hash { (a => 4, b => 5) }

sub debug_write { Exim::debug_write($_[0]); 'Wrote debug' }

sub log_write { Exim::log_write($_[0]); 'Wrote log' }

sub change_locale { setlocale(LC_TIME, 'fr_FR'); 'Changed locale' }

sub foo_warn { warn 'this is a warning'; 'Wrote warning' }

sub no_warn { $SIG{__WARN__} = sub { }; 'Discarded warnings' }

sub local_dns {
  my $resolver = Net::DNS::Resolver->new();
  my $pkt = $resolver ->search('example.com', 'NS');
  return $pkt->string;
}

sub no_intercept_dns {
  my $resolver = Net::DNS::Resolver->new(
    nameservers => [ '9.9.9.9' ],
    port        => 9953,
    );
  my $pkt = $resolver ->search('example.com', 'NS');
  return $pkt->string;
}
