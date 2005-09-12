# $Cambridge: exim/src/src/auths/Makefile,v 1.3 2005/09/12 13:50:03 ph10 Exp $

# Make file for building a library containing all the available authorization
# methods, and calling it auths.a. In addition, there are functions that are
# of general use in several methods; these are in separate modules so they are
# linked in only when needed. This Makefile is called from the main make file,
# after cd'ing to the auths subdirectory. When the relevant AUTH_ macros are
# defined, the equivalent modules herein is not included in the final binary.

OBJ = b64encode.o b64decode.o call_pam.o call_pwcheck.o call_radius.o \
      xtextencode.o xtextdecode.o get_data.o get_no64_data.o md5.o \
      cram_md5.o cyrus_sasl.o plaintext.o pwcheck.o sha1.o auth-spa.o spa.o

auths.a:         $(OBJ)
		 @$(RM_COMMAND) -f auths.a
		 @echo "$(AR) auths.a"
		 $(FE)$(AR) auths.a $(OBJ)
		 $(RANLIB) $@
		 @$(RM_COMMAND) -rf ../drtables.o

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

auth-spa.o:      $(HDRS) auth-spa.c
b64encode.o:     $(HDRS) b64encode.c
b64decode.o:     $(HDRS) b64decode.c
call_pam.o:      $(HDRS) call_pam.c
call_pwcheck.o:  $(HDRS) call_pwcheck.c pwcheck.h
call_radius.o:   $(HDRS) call_radius.c
get_data.o:      $(HDRS) get_data.c
get_no64_data.o: $(HDRS) get_no64_data.c
md5.o:           $(HDRS) md5.c
pwcheck.o:       $(HDRS) pwcheck.c pwcheck.h
sha1.o:          $(HDRS) sha1.c
xtextencode.o:   $(HDRS) xtextencode.c
xtextdecode.o:   $(HDRS) xtextdecode.c

cram_md5.o:      $(HDRS) cram_md5.c cram_md5.h
cyrus_sasl.o:    $(HDRS) cyrus_sasl.c cyrus_sasl.h
plaintext.o:     $(HDRS) plaintext.c plaintext.h
spa.o:           $(HDRS) spa.c spa.h

# End
