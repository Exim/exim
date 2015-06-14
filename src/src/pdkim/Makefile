# Make file for building the pdkim library.

OBJ = base64.o bignum.o pdkim.o rsa.o sha1.o sha2.o part-x509parse.o pdkim-rsa.o

pdkim.a:         $(OBJ)
		 @$(RM_COMMAND) -f pdkim.a
		 @echo "$(AR) pdkim.a"
		 $(FE)$(AR) pdkim.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) -I. $*.c

base64.o:           $(HDRS) base64.c
bignum.o:           $(HDRS) bignum.c
part-x509parse.o:   $(HDRS) part-x509parse.c
pdkim.o:            $(HDRS) pdkim.h pdkim-rsa.h pdkim.c
pdkim-rsa.o:        $(HDRS) polarssl/private-x509parse_c.h polarssl/base64.h \
			pdkim-rsa.h pdkim-rsa.c
rsa.o:              $(HDRS) rsa.c
sha1.o:             $(HDRS) sha1.c
sha2.o:             $(HDRS) sha2.c

# End
