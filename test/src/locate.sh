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
        `find /usr/lib/postgresql -name bin -type d`
HERE
  shift
done

