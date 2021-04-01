package Exim::Utils;
use v5.10.1;
use strict;
use warnings;
use File::Copy;
use parent 'Exporter';
our @EXPORT_OK = qw(uniq numerically cp);


sub uniq {
    my %uniq = map { $_, undef } @_;
    return keys %uniq;
}

sub numerically { $::a <=> $::b }

sub cp {
    if ($File::Copy::VERSION >= 2.15) { # since Perl 5.11 we should have >= 2.15
        return File::Copy::cp(@_);
    }
    copy(@_) or return undef;
    my ($src, $dst) = @_;
    my @st = stat $src or return undef;
    chmod($st[2]&07777, $dst);
}

1;
