# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the misc_modules subdirectory.
#
# Copyright (c) The Exim Maintainers 2024 - 2025

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/drivers-Makefile.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

# Ensure a non-empty .a since some platforms complain
OBJ += dummy.o

all:		miscmods.a $(MODS)
		$(FE):

miscmods.a:	$(OBJ)
		@$(RM_COMMAND) -f miscmods.a
		@echo "$(AR) miscmods.a"
		@$(AR) miscmods.a $(OBJ)
		$(RANLIB) $@

.SUFFIXES:      .o .c .so
.c.o:;          @echo "$(CC) $*.c"
		$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;         @echo "$(CC) -shared $*.c"
		$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) \
			$(SUPPORT_$*_INCLUDE) $(INCLUDE) $(DLFLAGS) $*.c \
			$(SUPPORT_$*_LIBS) -o $@

# Note that the sources from pdkim/ are linked into the build.../miscmods/ dir
# by scripts/Makelinks.
arc.o	arc.so:			$(HDRS) pdkim.h arc.c
dkim.o  dkim.so:		$(HDRS) dkim.h dkim.c dkim_transport.c \
				crypt_ver.h pdkim.h pdkim_hash.h pdkim.c \
				signing.h signing.c
dmarc.o dmarc.so:		$(HDRS) spf.h pdkim.h dmarc.h \
				dmarc.c dmarc_common.c
dmarc_native.o dmarc_native.so:	$(HDRS) spf.h pdkim.h dmarc.h \
				dmarc_native.c dmarc_common.c
dscp.o  dscp.so:		$(HDRS) dscp.c
dummy.o:			dummy.c
exim_filter.o	exim_filter.so:	$(HDRS) exim_filter.c
pam.o   	pam.so:		$(HDRS) pam.c
perl.o		perl.so:       	$(HDRS) perl.c
proxy.o		proxy.so:	$(HDRS) proxy_api.h proxy.c
radius.o	radius.so:	$(HDRS) radius.c
sieve_filter.o	sieve_filter.so: $(HDRS) sieve_filter.c
socks.o		socks.so:	$(HDRS) socks_api.h ../transports/smtp.h socks.c
spf.o   	spf.so:		$(HDRS) spf.h spf.c
spf_perl.o	spf_perl.so:	$(HDRS) spf.h spf_perl.c
xclient.o	xclient.so:	$(HDRS) xclient_api.h xclient.c



# We need a single .o because that's what scripts/Configure-Makefile
# understands and fills in to $(OBJ).
# Try desparately to get the Solaris cc/ld to build one.
dkim.o:
	@echo "$(CC) dkim.c dkim_transport.c pdkim.c signing.c"
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) dkim.c
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) dkim_transport.c
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) pdkim.c
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $(TLS_INCLUDE) signing.c
	$(FE)mv dkim.o dkim_tmp.o
	$(FE)$(LD) -r -o dkim.o $(LDFLAGS_PARTIAL) \
		dkim_tmp.o dkim_transport.o pdkim.o signing.o

# Similarly, we want a single .so for the dynamic-load module
dkim.so:
	@echo "$(CC) -shared dkim.c dkim_transport.c pdkim.c signing.c"
	$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) \
		$(SUPPORT_$*_INCLUDE) $(INCLUDE) $(TLS_INCLUDE) $(DLFLAGS) \
		dkim.c dkim_transport.c pdkim.c signing.c $(SUPPORT_$*_LIBS)  \
		-o $@

# spf_perl is special; Configure-Makefile asks for it but we actually
# build resulting in a file named spf.so because the module-loading
# in Exim needs the file named to match the module-name string its
# clients search for.
# This is sub-optimal; spf_perl.c gets recompiled every build.

spf_perl.so:
	@echo "$(CC) -shared $*.c"
	$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) \
		$(SUPPORT_SPF_PERL_INCLUDE) $(INCLUDE) $(DLFLAGS) \
		spf_perl.c $(SUPPORT_SPF_PERL_LIBS) -o spf.so

# DMARC
dmarc.o dmarc_native.o:
	@echo "$(CC) $*.c dmarc_common.c"
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c
	$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) dmarc_common.c
	$(FE)mv $@ dmarc_tmp.o
	$(FE)ld -r -o $@ $(LDFLAGS_PARTIAL) dmarc_tmp.o dmarc_common.o

# dmarc_native is special in the same way as spf_perl
dmarc.so dmarc_native.so:
	@echo "$(CC) -shared $*.c dmarc_common.c"
	$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) \
		$(SUPPORT_$*_INCLUDE) $(INCLUDE) $(TLS_INCLUDE) $(DLFLAGS) \
		$*.c dmarc_common.c $(SUPPORT_$*_LIBS) -o dmarc.so

# Compile instructions for static perl.o for when EXIM_PERL is set
# Dynamic is managed all via scripts/Configure-Makefile

perl.o:
	@echo "$(PERL_CC) perl.c"
	$(FE)$(PERL_CC) $(PERL_CCOPTS) $(CFLAGS) $(INCLUDE) -c perl.c

# End
