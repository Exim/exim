use Test::More;
use lib 'lib';
use_ok 'Exim::Runtest' or BAIL_OUT 'Can not load the module';

can_ok 'Exim::Runtest', qw(mailgroup dynamic_socket);

subtest 'mailgroup' => sub {
    my $group = getgrgid $(;
    ok $group => 'got a group name';
    diag "use group $group";

    is Exim::Runtest::mailgroup($group), $group => 'group names match';
    ok $group = Exim::Runtest::mailgroup('non existing group') => 'cope with unknown group';
    diag "got random group: $group";

    ok getgrnam($group) => 'got an existing group';
};

subtest 'dynamic_socket' => sub {
    ok my $socket = Exim::Runtest::dynamic_socket() => 'got a socket';
    diag "got socket on port @{[$socket->sockport]}";
    isa_ok $socket => 'IO::Socket::INET';
    cmp_ok $socket->sockport(), '>=', 1024 => 'port is >= 1024';
    $socket->close;
};


done_testing;
