# $Cambridge: exim/src/src/pdkim/Makefile,v 1.1.2.1 2009/02/24 13:13:47 tom Exp $

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
bignum.o:           $(HDRS) base64.c
pdkim.o:            $(HDRS) base64.c
rsa.o:              $(HDRS) base64.c
sha1.o:             $(HDRS) base64.c
sha2.o:             $(HDRS) base64.c

# End
