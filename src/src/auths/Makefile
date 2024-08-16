# Make file for building a library containing all the available authorization
# methods, and calling it auths.a. In addition, there are functions that are
# of general use in several methods; these are in separate modules so they are
# linked in only when needed. This Makefile is called from the main make file,
# after cd'ing to the auths subdirectory. When the relevant AUTH_ macros are
# defined, the equivalent modules herein is not included in the final binary.
#
# Copyright (c) The Exim Maintainers 2024

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/drivers-Makefile with
#     definitions from scripts/Configure-Makefile

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

OBJ += auth-spa.o call_pam.o call_pwcheck.o call_radius.o check_serv_cond.o \
	get_data.o get_no64_data.o pwcheck.o

all:		auths.a $(MODS)

auths.a:	$(OBJ)
		@$(RM_COMMAND) -f auths.a
		@echo "$(AR) auths.a"
		$(FE)$(AR) auths.a $(OBJ)
		$(RANLIB) $@

.SUFFIXES:	.o .c .so
.c.o:;		@echo "$(CC) $*.c"
		$(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

SO_FLAGS = -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS)
.c.so:;		@echo "$(CC) -shared $*.c"
		$(FE)$(CC) $(SO_FLAGS) $(AUTH_$*_INCLUDE) $(AUTH_$*_LIBS) \
			$*.c -o $@


$(OBJ) $(MOD): $(HDRS)

auth-spa.o:         auth-spa.c
call_pam.o:         call_pam.c
call_pwcheck.o:     call_pwcheck.c pwcheck.h
call_radius.o:      call_radius.c
check_serv_cond.o:  check_serv_cond.c
get_data.o:         get_data.c
get_no64_data.o:    get_no64_data.c
pwcheck.o:          pwcheck.c pwcheck.h

cram_md5.o:         cram_md5.c cram_md5.h
cyrus_sasl.o:       cyrus_sasl.c cyrus_sasl.h
dovecot.o:          dovecot.c dovecot.h
external.o:         external.c external.h
gsasl.o:	    gsasl.c gsasl.h
heimdal_gssapi.o:   heimdal_gssapi.c heimdal_gssapi.h
plaintext.o:        plaintext.c plaintext.h
spa.o:              spa.c spa.h
tls.o:              tls.c tls.h

# These depend on more than one .c source

spa.so:	spa.c auth-spa.c spa.h
	$(FE)$(CC) $(SO_FLAGS) spa.c auth-spa.c -o $@

# End
