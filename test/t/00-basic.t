use Test::More;
use Test::Pod::Coverage;
use Test::Exception;

use lib 'lib';
use_ok 'Exim::Runtest', qw(:all) or BAIL_OUT 'Can not load the module';

can_ok 'Exim::Runtest', qw(mailgroup dynamic_socket exim_binary);
pod_coverage_ok 'Exim::Runtest' => 'docs complete';

subtest 'mailgroup' => sub {
    my $group = getgrgid $(;
    ok $group => 'got a group name';
    note "use group $group";

    is mailgroup($group), $group => 'group names match';
    ok $group = mailgroup('non existing group') => 'cope with unknown group';
    note "got random group: $group";

    ok getgrnam($group) => 'got an existing group';

    dies_ok { mailgroup(22) } 'dies on numeric group';
    dies_ok { mailgroup() } 'dies on missing default group';
};

subtest 'dynamic_socket' => sub {
    ok my $socket = dynamic_socket() => 'got a socket';
    note "got socket on port @{[$socket->sockport]}";
    isa_ok $socket => 'IO::Socket::INET';
    cmp_ok $socket->sockport(), '>=', 1024 => 'port is >= 1024';
    $socket->close;
};

subtest 'exim_binary' => sub {
    my @argv1 = qw(/bin/sh a b);
    my @argv2 = qw(t/samples/foo a b);
    chomp(my $cwd = `pwd`); # don't use Cwd, as we use Cwd in the tested module already
    is_deeply [exim_binary(@argv1)], \@argv1 => 'got the binary as abs path from argv';
    is_deeply [exim_binary(@argv2)], ["$cwd/t/samples/foo", @argv2[1,$#argv2]] => 'got the binary as rel path from argv';
};

done_testing;
