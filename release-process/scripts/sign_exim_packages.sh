#!/bin/sh
#
# gpg signs the package set.
# key used set from env var EXIM_KEY, script defaults that to Nigel's.
# woe betide the poor sod who does not use a gpg agent, so has
# to enter their password for every file...
#

: ${EXIM_KEY:=nigel@exim.org}

for file in *.tar.gz *.tar.bz2 *.tar.lz
do
  gpg  --local-user ${EXIM_KEY} --detach-sig --armor $file
done
