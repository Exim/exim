package Exim::Runtest;
use strict;
use warnings;
use Carp;

use List::Util qw'shuffle';


# find a group name, preferrable 'mail', but
# use some other random name if 'mail' isn't a valid group
# name
sub mailgroup {
    my $group = shift;

    croak "Need a group *name*, not a numeric group id."
        if $group =~ /^\d+$/;

    return $group if getgrnam $group;

    my @groups;
    setgrent or die "setgrent: $!\n";
    push @groups, $_ while defined($_ = getgrent);
    endgrent;
    return (shuffle @groups)[0];
};


1;
