# The Exim Project does not use GitHub Issues

Hey, we want your input, but we want to make sure that we actually see it and
that your help is not wasted, so please read this.

The GitHub repo exists for convenience for some folks, and to host our Wiki.
The Git repo is an automated clone of our real repo over at
<https://git.exim.org/exim.git>.

Sometimes a maintainer will take a look at GitHub pull requests, just because
we care about the software and want to know about issues, but expect long
delays.  It's not a really supported workflow.

Our bug-tracker takes code-patches and is the place to go:
<https://bugs.exim.org/>

If you've found a security bug, then please email <security@exim.org>.
All Exim Maintainers can and do use PGP.
Keyring: <https://ftp.exim.org/pub/exim/Exim-Maintainers-Keyring.asc>
We don't have a re-encrypting mailer, just encrypt to all of them please.

## If this is too much hassle ...

We do periodically get around to checking GitHub Pull Requests.
It just won't be fast.

Patches should update the documentation, `doc/doc-docbook/spec.xfpt`; if you
like, just provide the plaintext which should go in there and we can mark it
up.

If it's a whole new feature, then please guard it with a build
option `EXPERIMENTAL_FOO`; docs are in plaintext in
`doc/doc-txt/experimental-spec.txt`.

If you're feeling particularly thorough, these files get updated too:
* `doc/doc-txt/ChangeLog` : all changes; workflow pre-dates Git
* `doc/doc-txt/NewStuff` : if it's a change in intended behavior which postmasters should read
* `doc/doc-txt/OptionLists.txt` : (we usually defer this until cutting a release)
* `src/README.UPDATING` : if you're breaking backwards compatibility

Thanks!
