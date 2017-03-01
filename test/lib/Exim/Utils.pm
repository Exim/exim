package Exim::Utils;
use v5.10.1;
use strict;
use warnings;
use parent 'Exporter';
our @EXPORT_OK = qw(uniq numerically);


sub uniq {
    my %uniq = map { $_, undef } @_;
    return keys %uniq;
}

sub numerically { $::a <=> $::b }

1;
