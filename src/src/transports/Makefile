# Make file for building a library containing all the available transports and
# calling it transports.a. This is called from the main make file, after cd'ing
# to the transports subdirectory.
#
# Copyright (c) The Exim Maintainers 2021 - 2024

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/drivers-Makefile with
#     definitions from scripts/Configure-Makefile.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

OBJ += smtp_socks.o tf_maildir.o

all:		transports.a $(MODS)

transports.a:    $(OBJ) smtp_socks.o tf_maildir.o
		 @$(RM_COMMAND) -f transports.a
		 @echo "$(AR) transports.a"
		 @$(AR) transports.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c .so
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;          @echo "$(CC) -shared $*.c"
		 $(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@


$(OBJ) $(MOD): $(HDRS)

appendfile.o:			appendfile.c appendfile.h tf_maildir.h
autoreply.o autoreply.so:	autoreply.c autoreply.h
lmtp.o lmtp.so:			lmtp.c lmtp.h
pipe.o pipe.so:			pipe.c pipe.h
queuefile.o queuefile.so:	queuefile.c queuefile.h
smtp.o:				smtp.c smtp.h
smtp_socks.o:			smtp_socks.c smtp.h

tf_maildir.o:			tf_maildir.c tf_maildir.h appendfile.h



# This depends on more than one .c source

appendfile.so: appendfile.c appendfile.h tf_maildir.c tf_maildir.h
	@echo "$(CC) -shared appendfile.c tf_maildir.c"
	$(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) \
		appendfile.c tf_maildir.c -o $@

# End
