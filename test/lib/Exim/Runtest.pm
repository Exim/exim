package Exim::Runtest;
use strict;
use warnings;
use IO::Socket::INET;
use Carp;

use List::Util qw'shuffle';

=head1 NAME

Exim::Runtest - helper functions for the runtest script

=head1 SYNOPSIS

 use Exim::Runtest;
 my $foo = Exim::Runtest::foo('foo');

=head1 DESCRIPTION

The B<Exim::Runtest> module provides some simple functions
for the F<runtest> script. No functions are exported yet.

=cut

sub mailgroup {
    my $group = shift // croak "Need a default group name.";

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

__END__

=head1 FUNCTIONS

=over

=item B<mailgroup>(I<$default>)

Check if the mailgroup I<$default> exists. Return the checked
group name or some other random but existing group.

=item B<dynamic_socket>()

Return a dynamically allocated listener socket in the range
between 1024 and 65534;

=back

=cut
