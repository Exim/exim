#! /bin/sh
# Copyright (c) The Exim Maintainers 2022 - 2025
# SPDX-License-Identifier: GPL-2.0-or-later


# Shell script to create a link to the appropriate OS-specific header file.

scripts=../scripts

# Get the OS type, and check that there is a make file for it.

os=`$scripts/os-type -generic` || exit 1

if	test ! -r ../OS/Makefile-$os
then    echo ""
	echo "*** Sorry - operating system $os is not supported"
        echo "*** See OS/Makefile-* for supported systems" 1>&2
        echo ""
	exit 1;
fi

# Ensure there is an OS-specific header file, and link it to os.h. There should
# always be one if there is a make file for the OS, so its absence is somewhat
# disastrous.

if	test ! -r ../OS/os.h-$os
then    echo ""
	echo "*** Build error: OS/os.h-$os file is missing"
        echo ""
	exit 1;
fi
rm -f os.h

# In order to accommodate for the fudge below, copy the file instead of
# symlinking it. Otherwise we pollute the clean copy with the fudge.
cp -p ../OS/os.h-$os os.h || exit 1

# Special-purpose fudges for MUSL and older linuxes, if we are not
# one of those, then stop here

if [ "$os" != "Linux" -a "$os" != "Linux-libc5" ] ; then exit 0; fi

grep ip_options /usr/include/linux/ip.h >/dev/null
if [ $? = 0 ] ; then exit 0; fi

grep 'struct ip_opts' /usr/include/netinet/in.h >/dev/null 2>/dev/null
if [ $? = 0 ]
then

cat >>os.h <<End

/* Signal that we are actually inside MUSL */

#undef GLIBC_IP_OPTIONS
#define MUSL_IP_OPTIONS
End

else

cat >>os.h <<End

/* Fudge added because this Linux doesn't appear to have a definition
for ip_options in /usr/include/linux/ip.h. */

#define ip_options options
End

fi
