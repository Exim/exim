package Exim::Runtest;
use 5.010;
use strict;
use warnings;
use File::Basename;
use IO::Socket::INET;
use Cwd;
use Carp;

use Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(mailgroup dynamic_socket exim_binary flavour flavours);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

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

sub exim_binary {

    # two simple cases, absolute path or relative path and executable
    if (@_) {
        return @_ if $_[0] =~ /^\//;
        return Cwd::abs_path(shift), @_ if -x $_[0];
    }

    # so we're still here, if the simple approach didn't help.

    # if there is '../exim-snapshot/<build-dir>/exim', use this
    # if there is '../exim4/<build-dir>/exim', use this
    # if there is '../exim-*.*/<build-dir>/exim', use the one with the highest version
    #   4.84 < 4.85RC1 < 4.85RC2 < 4.85 < 4.86RC1 < … < 4.86
    # if there is '../src/<build-dir>', use this
    #

    my $prefix = '..';  # was intended for testing.

    # get a list of directories having the "scripts/{os,arch}-type"
    # scripts
    my @candidates = grep { -x "$_/scripts/os-type" and -x "$_/scripts/arch-type" }
        "$prefix/exim-snapshot", "$prefix/exim4", # highest priority
        (reverse sort {                           # list of exim-*.* directories
        # split version number from RC number
        my @a = ($a =~ /(\d+\.\d+)(?:RC(\d+))?/);
        my @b = ($b =~ /(\d+\.\d+)(?:RC(\d+))?/);
        # if the versions are not equal, we're fine,
        # but otherwise we've to compare the RC number, where an
        # empty RC number is better than a non-empty
        ($a[0] cmp $b[0]) || (defined $a[1] ? defined $b[1] ? $a[1] cmp $b[1] : -1 : 1)
        } glob "$prefix/exim-*.*"),
        "$prefix/src";                       # the "normal" source

    # binaries should be found now depending on the os-type and
    # arch-type in the directories we got above
    my @binaries = grep { -x }
        map { ("$_/exim", "$_/exim4") }
        map {
            my $os = `$_/scripts/os-type`;
            my $arch = `$_/scripts/arch-type`;
            chomp($os, $arch);
            ($ENV{build} ? "$_/build-$ENV{build}" : ()),
            "$_/build-$os-$arch" . ($ENV{EXIM_BUILD_SUFFIX} ? ".$ENV{EXIM_BUILD_SUFFIX}" : '');
        } @candidates;

    return $binaries[0], @_;
}

sub flavour {
    my $etc = '/etc';

    if (@_) {
        croak "do not pass a directory, it's for testing only"
            unless $ENV{HARNESS_ACTIVE};
        $etc = shift;
    }

    if (open(my $f, '<', "$etc/os-release")) {
        local $_ = join '', <$f>;
        my ($id) = /^ID="?(.*?)"?\s*$/m;
        my $version = /^VERSION_ID="?(.*?)"?\s*$/m ? $1 : '';
        return "$id$version";
    }

    if (open(my $f, '<', "$etc/debian_version")) {
        chomp(local $_ = <$f>);
        $_ = int $_;
        return "debian$_";
    }

    undef;
}

sub flavours {
    my %h = map { /\.(\S+)$/, 1 }
            grep { !/\.orig$/ } glob('stdout/*.*'), glob('stderr/*.*');
    return sort keys %h;
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

=item ($binary, @argv) = B<exim_binary>(I<@argv>)

Find the Exim binary. Consider the first element of I<@argv>
and remove it from I<@argv>, if it is an executable binary.
Otherwise search the binary (while honouring C<EXIM_BUILD_SUFFIX>,
C<../scripts/os-type> and C<../os-arch>) and return the
the path to the binary and the unmodified I<@argv>.

=item B<flavour>()

Find a hint for the current flavour (Linux distro). It does so by checking
typical files in the F</etc> directory.

=item B<flavours>()

Return a list of available flavours. It does so by scanning F<stdout/> and
F<stderr/> for I<flavour> files (extensions after the numerical prefix.

=back

=cut
