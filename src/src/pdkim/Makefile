# Make file for building the pdkim library.

OBJ = pdkim.o hash.o rsa.o

pdkim.a:         $(OBJ)
		 @$(RM_COMMAND) -f pdkim.a
		 @echo "$(AR) pdkim.a"
		 $(FE)$(AR) pdkim.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) -I. $*.c

pdkim.o:            $(HDRS) crypt_ver.h hash.h blob.h pdkim.h pdkim.c
hash.o:             $(HDRS) crypt_ver.h hash.h blob.h pdkim.h hash.c
rsa.o:              $(HDRS) crypt_ver.h rsa.h blob.h rsa.c

# End
