package Exim::Runtest;
use strict;
use warnings;
use IO::Socket::INET;
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
}

sub dynamic_socket {
    my $socket;
    for (my $port = 1024; $port < 65000; $port++) {
        $socket = IO::Socket::INET->new(
            LocalHost => '127.0.0.1',
            LocalPort => $port,
            Listen => 10,
            ReuseAddr => 1,
        ) and return $socket;
    }
    croak 'Can not allocate a free port.';
}

1;
