#!/bin/sh

[ -d bin.sys ] || mkdir bin.sys
cd bin.sys

while [ $# -gt 0 ]
do
  while read d
  do
    if [ -x $d/$1 ]
    then
      rm -f ./$1
      ln -s $d/$1 .
      break
    fi
  done <<-HERE
	/bin
	/usr/bin
	/usr/sbin
	/usr/libexec
	/usr/local/bin
	/usr/lib/postgresql/10/bin
	/usr/lib/postgresql/9.5/bin
	/usr/lib/postgresql/9.4/bin
	/usr/lib/postgresql/9.3/bin
	/usr/lib/postgresql/9.2/bin
	/usr/lib/postgresql/9.1/bin
	/usr/lib/postgresql/9/bin
HERE
  shift
done

