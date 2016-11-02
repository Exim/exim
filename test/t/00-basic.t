use Test::More;
use lib 'lib';
use_ok 'Exim::Runtest';

can_ok 'Exim::Runtest', qw(mailgroup);

my $group = getgrgid $(;
ok $group => 'got a group name';
diag "use group $group";

is Exim::Runtest::mailgroup($group), $group => 'group names match';
ok $group = Exim::Runtest::mailgroup('non existing group') => 'cope with unknown group';
diag "got random group: $group";

ok getgrnam($group) => 'got an existing group';



done_testing;
