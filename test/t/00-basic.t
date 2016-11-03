use Test::More;
use lib 'lib';
use_ok 'Exim::Runtest' or BAIL_OUT 'Can not load the module';

can_ok 'Exim::Runtest', qw(mailgroup);

subtest 'mailgroup' => sub {
    my $group = getgrgid $(;
    ok $group => 'got a group name';
    diag "use group $group";

    is Exim::Runtest::mailgroup($group), $group => 'group names match';
    ok $group = Exim::Runtest::mailgroup('non existing group') => 'cope with unknown group';
    diag "got random group: $group";

    ok getgrnam($group) => 'got an existing group';
};



done_testing;
