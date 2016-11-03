use Test::More;
use Test::Pod::Coverage;
use Test::Exception;

use lib 'lib';
use_ok 'Exim::Runtest', qw(:all) or BAIL_OUT 'Can not load the module';

can_ok 'Exim::Runtest', qw(mailgroup dynamic_socket);
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


done_testing;
