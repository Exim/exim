# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the misc_modulessubdirectory.
#
# Copyright (c) The Exim Maintainers 2024

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/lookups-Makefile.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

OBJ += dummy.o

all:		miscmods.a $(MODS)

miscmods.a:	$(OBJ)
		@$(RM_COMMAND) -f miscmods.a
		@echo "$(AR) miscmods.a"
		@$(AR) miscmods.a $(OBJ)
		$(RANLIB) $@

.SUFFIXES:      .o .c .so
.c.o:;          @echo "$(CC) $*.c"
		$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;         @echo "$(CC) -shared $*.c"
		$(FE)$(CC) $(SUPPORT_$*_INCLUDE) $(SUPPORT_$*_LIBS) \
			-DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) \
			$(DLFLAGS) $*.c -o $@

# Note that the sources from pdkim/ are linked into the build.../miscmods/ dir
# by scripts/Makelinks.
arc.o	arc.so:		$(HDRS) pdkim.h arc.c
dkim.o  dkim.so:	$(HDRS) dkim.h dkim.c dkim_transport.c \
			crypt_ver.h pdkim.h pdkim_hash.h pdkim.c \
			signing.h signing.c
dmarc.o dmarc.so:	$(HDRS) pdkim.h dmarc.h dmarc.c
dummy.o:		dummy.c
pam.o   pam.so:		$(HDRS) pam.c
radius.o radius.so:	$(HDRS) radius.c
spf.o   spf.so:		$(HDRS) spf.h spf.c

dkim.o:
		@echo "$(CC) dkim.c dkim_transport.c pdkim.c signing.c"
		$(FE)$(CC) -r $(LDFLAGS_PARTIAL) -o $@ $(CFLAGS) $(INCLUDE) \
			dkim.c dkim_transport.c pdkim.c signing.c

dkim.so:
		@echo "$(CC) -shared dkim.c dkim_transport.c pdkim.c signing.c"
		$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) -o $@ \
			$(SUPPORT_$*_INCLUDE) $(SUPPORT_$*_LIBS) \
			$(CFLAGS) $(INCLUDE) $(DLFLAGS) \
			dkim.c dkim_transport.c pdkim.c signing.c

# End
