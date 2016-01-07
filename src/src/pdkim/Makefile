# Make file for building the pdkim library.

OBJ = pdkim.o

pdkim.a:         $(OBJ)
		 @$(RM_COMMAND) -f pdkim.a
		 @echo "$(AR) pdkim.a"
		 $(FE)$(AR) pdkim.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) -I. $*.c

part-x509parse.o:   $(HDRS) crypt_ver.h part-x509parse.c
pdkim.o:            $(HDRS) crypt_ver.h pdkim.h pdkim.c
sha1.o:             $(HDRS) crypt_ver.h sha1.c
sha2.o:             $(HDRS) crypt_ver.h sha2.c

# End
