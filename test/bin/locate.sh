#!/bin/sh

[ -e bin.sys ] || mkdir bin.sys
cd bin.sys

while read d
do
  if [ -x $d/$1 ]
  then
    while [ $# -gt 0 ]
    do
      rm -f ./$1
      ln -s $d/$1 .
      shift
    done
  fi
done <<-HERE
	/bin
	/usr/bin
	/usr/local/bin
	/usr/lib/postgresql/10/bin
	/usr/lib/postgresql/9/bin
HERE

