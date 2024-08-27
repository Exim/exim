# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the misc_modulessubdirectory.
#
# Copyright (c) The Exim Maintainers 2024

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/lookups-Makefile.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE


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
		$(FE)$(CC) $(SUPPORT_$*_INCLUDE) $(SUPPORT_$*_LIBS) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@

spf.o spf.so:	$(HDRS) spf.h spf.c

# End
