#!/bin/sh
#
# $Cambridge: exim/release-process/scripts/sign_exim_packages.sh,v 1.1 2010/06/03 12:00:38 nm4 Exp $
#
# gpg signs the package set.
# key used set from env var EXIM_KEY, script defaults that to Nigel's.
# woe betide the poor sod who does not use a gpg agent, so has
# to enter their password for every file...
#

: ${EXIM_KEY:=nigel@exim.org}


for file in *.tar.gz *.tar.bz2
do
  gpg  --local-user ${EXIM_KEY} --detach-sig --armor $file
done
