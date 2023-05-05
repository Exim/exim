#!/usr/bin/env perl

use 5.010;
use strict;
use warnings;
use File::Find;
use Cwd;

my @dirs = grep { /^\// && -d } split(/:/, $ENV{PATH}), qw(
  /bin
  /usr/bin
  /usr/sbin
  /usr/lib
  /usr/libexec
  /usr/local/bin
  /usr/local/sbin
  /usr/local
  /opt
);

my %path = map { $_ => locate($_, @dirs) } @ARGV;

mkdir 'bin.sys'
  or die "bin.sys: $!"
  if not -d 'bin.sys';

foreach my $tool (keys %path) {
    next if not defined $path{$tool};
    print "$tool $path{$tool}\n";

    unlink "bin.sys/$tool";
    symlink $path{$tool}, "bin.sys/$tool"
      or warn "bin.sys/$tool -> $path{$tool}: $!\n";
}

sub locate {
    my ($tool, @dirs) = @_;

    my $n = 0;
    for ( my @look_in = map { $_.'/' } @dirs; @look_in ;) {
        my $d = shift @look_in;
            printf STDERR "\r%7u %s\e[K", ++$n, $d;
        my $p = "$d/$tool";
        -x $p && -f _ and do {
            printf STDERR "\r\e[K";
            return $p;
        };
        push @look_in, glob $d.'*/'
            unless $d =~ m{bin/$};
    }

    return;

    # use die to break out of the find as soon
    # as we found it
    my $cwd = cwd;
    eval {
        find(
            sub {
                return $File::Find::prune = 1 unless -r -x -r;
                return unless $tool eq $_ and -x and -f _;
                die { found => $File::Find::name };
            },
            @dirs
        );
    };
    chdir $cwd;

    return ref $@ eq 'HASH' && $@->{found} || undef;
}
