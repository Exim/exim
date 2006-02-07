use POSIX qw(locale_h);

sub foo { "Subroutine foo called with args: @_"; }

sub foo_undef { $x; }

sub foo_die { die "expiring..."; }

sub readvar { Exim::expand_string("\$$_[0]"); }

sub return_scalar { 42; }

sub return_list { (10,20,30); }

sub return_variable_vector { @x = (4,5,6); @x; }

sub return_hash { %x = ("a", 4, "b", 5); %x; }

sub debug_write { Exim::debug_write("$_[0]"); "Wrote debug"; }

sub log_write { Exim::log_write("$_[0]"); "Wrote log"; }

sub change_locale { setlocale(LC_TIME, "fr_FR"); "Changed locale"; }

sub foo_warn { warn "this is a warning"; "Wrote warning"; }

sub no_warn { $SIG{__WARN__} = sub { }; "Discarded warnings"; }
