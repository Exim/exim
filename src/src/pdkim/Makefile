# $Cambridge: exim/src/src/pdkim/Makefile,v 1.2 2009/06/10 07:34:05 tom Exp $

OBJ = base64.o bignum.o pdkim.o rsa.o sha1.o sha2.o

pdkim.a:         $(OBJ)
		 @$(RM_COMMAND) -f pdkim.a
		 @echo "$(AR) pdkim.a"
		 $(FE)$(AR) pdkim.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

base64.o:           $(HDRS) base64.c
bignum.o:           $(HDRS) bignum.c
pdkim.o:            $(HDRS) pdkim.c
rsa.o:              $(HDRS) rsa.c
sha1.o:             $(HDRS) sha1.c
sha2.o:             $(HDRS) sha2.c

# End
