# Top-level makefile for Exim; handles creating a build directory with
# appropriate links, and then creating and running the main makefile in that
# directory.

# Copyright (c) The Exim Maintainers 2022 - 2023
# Copyright (c) University of Cambridge, 1995 - 2018
# SPDX-License-Identifier: GPL-2.0-or-later
# See the file NOTICE for conditions of use and distribution.

# IRIX make uses the shell that is in the SHELL variable, which often defaults
# to csh, so put this in to make it use the Bourne shell. In systems where
# /bin/sh is not a Bourne-compatible shell, this line will have to be edited,
# or "make" must be called with a different SHELL= setting.

SHELL=/bin/sh
RM_COMMAND=/bin/rm

# The buildname defaults to "<os-type>-<arch-type>". It can be
# overridden by the "build" parameter when invoking make (e.g. make
# build=xxx) This does not provide an override for the OS type and
# architecture type used during the build process; they still have to be
# used for the OS-specific files. To override them, you can set the
# shell variables OSTYPE and ARCHTYPE when running make.
#
# EXIM_BUILD_SUFFIX gets appended to the buildname.  (This enables
# parallel builds on a file system shared among different Linux distros
# (same os-type, same arch-type). The ../test/runtest script honours the
# EXIM_BUILD_SUFFIX when searching the Exim binary.)

buildname=$${build:-`$(SHELL) scripts/os-type`-`$(SHELL) scripts/arch-type`}$${EXIM_BUILD_SUFFIX:+.$$EXIM_BUILD_SUFFIX}

# The default target checks for the existence of Local/Makefile, that the main
# makefile is built and up-to-date, and then it runs it.
# If Local/Makefile-<buildname> exists, it is read too.

all: Local/Makefile configure
	@cd build-$(buildname); $(MAKE) SHELL=$(SHELL) $(MFLAGS)

# This pair for the convenience of of the Debian maintainers
exim utils: Local/Makefile configure
	@cd build-$(buildname); $(MAKE) SHELL=$(SHELL) $(MFLAGS) $@

# For testsuite builds
exim_openssl exim_gnutls: Local/Makefile configure
	@cd build-$(buildname); $(MAKE) SHELL=$(SHELL) $(MFLAGS) $@

Local/Makefile:
	@echo ""
	@echo "*** Please create Local/Makefile by copying src/EDITME and making"
	@echo "*** appropriate changes for your site."
	@echo ""
	@test ! -d Local && mkdir Local
	@false

# This is separated off so that "make build-directory" can be obeyed on
# its own if necessary.

build-directory:
	@builddir=build-$(buildname); \
	case "$$builddir" in *UnKnown*) exit 1;; esac; \
	$(SHELL) -c "test -d $$builddir -a -r $$builddir/version.c || \
	  (mkdir $$builddir; cd $$builddir; $(SHELL) ../scripts/MakeLinks)";

checks:
	$(SHELL) scripts/source_checks

# The "configure" target ensures that the build directory exists, then arranges
# to build the main makefile from inside the build directory, by calling the
# Configure-Makefile script. This does its own dependency checking because of
# the optional files.

configure: checks build-directory
	@cd build-$(buildname); \
	  build=$(build) $(SHELL) ../scripts/Configure-Makefile

# The "makefile" target forces a rebuild of the makefile (as opposed to
# "configure", which doesn't force it).

makefile: build-directory
	@cd build-$(buildname); $(RM_COMMAND) -f Makefile; \
	  build=$(build) $(SHELL) ../scripts/Configure-Makefile

# The installation commands are kept in a separate script, which expects
# to be run from inside the build directory.

install:        all
		@cd build-$(buildname); \
		build=$(build) $(SHELL) ../scripts/exim_install $(INSTALL_ARG)

# Tidy-up targets

clean:; @echo ""; echo '*** "make clean" just removes all .o and .a files'
	@echo '*** Use "make makefile" to force a rebuild of the makefile'
	@echo ""
	cd build-$(buildname); \
	$(RM_COMMAND) -f *.o lookups/*.o lookups/*.a auths/*.o auths/*.a \
	routers/*.o routers/*.a transports/*.o transports/*.a \
	pdkim/*.o pdkim/*.a

clean_exim:; cd build-$(buildname); \
	 $(RM_COMMAND) -f *.o lookups/*.o lookups/*.a auths/*.o auths/*.a \
	routers/*.o routers/*.a transports/*.o transports/*.a lookups/*.so

distclean:; $(RM_COMMAND) -rf build-* cscope*

cscope.files: FRC
	echo "-q" > $@
	echo "-p3" >> $@
	-bd=build-$(buildname); [ -d $$bd ] && echo -e "$$bd/config.h\n$$bd/Makefile" >> $@
	find src Local OS exim_monitor -name "*.[cshyl]" -print \
		    -o -name "os.[ch]*" -print \
		    -o -name "*akefile*" -print \
		    -o -name config.h.defaults -print \
		    -o -name EDITME -print >> $@

FRC:

# End of top-level makefile
