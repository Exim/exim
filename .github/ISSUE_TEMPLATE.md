# The Exim Project does not use GitHub Issues

Hey, we want your input, but we want to make sure that we actually see it and
that your help is not wasted, so please read this.

The GitHub repo exists for convenience for some folks, and to host our Wiki.
The Git repo is an automated clone of our real repo over at
<https://git.exim.org/exim.git>.

Sometimes a maintainer will take a look at GitHub issues, just because we care
about the software and want to know about issues, but expect long delays.
It's not a really supported workflow.

If you need help with configuration, or _think_ you've found a bug, then the
Exim Users mailing-list is the place to start.  Many experienced postmasters
hang out there: <https://lists.exim.org/mailman/listinfo/exim-users>

Our documentation is _very_ extensive and if the behavior does not match the
documentation, then that's a bug to be reported.
<https://www.exim.org/docs.html>
In addition, if using Debian or a derivative (such as *Ubuntu*), then you
should read: <https://pkg-exim4.alioth.debian.org/README/README.Debian.html>

If you're absolutely sure it's a bug, and it's not a security problem, then
our Bugzilla is the main place to go: <https://bugs.exim.org/>

If you've found a security bug, then please email <security@exim.org>.
All Exim Maintainers can and do use PGP.
Keyring: <https://ftp.exim.org/pub/exim/Exim-Maintainers-Keyring.asc>
We don't have a re-encrypting mailer, just encrypt to all of them please.


## If you MUST file an issue on GitHub

Read "How to Report Bugs Effectively":
<https://www.chiark.greenend.org.uk/~sgtatham/bugs.html>

Please include the OS details, output of `exim -d -bV 2>/dev/null`
and as much information as you think is relevant.

Thanks.
