# Unix base make file for xfpt.

# The normal targets in this Makefile are not called directly, but should be
# called from the top-level Makefile. To make it easy when developing from
# within the source directory, a call with no target gets passed back up to
# the outer Makefile.

intcall:;      cd ..; $(MAKE);

# This is the main target

all:  xfpt

# Compile step for the modules

.SUFFIXES:  .o .c
.c.o:;  @echo "$(CC) $*.c"
	       $(FE)$(CC) -c $(CFLAGS) -DDATADIR='"$(DATADIR)"' $*.c

# List of general dependencies

DEP = ../Makefile Makefile xfpt.h structs.h functions.h globals.h mytypes.h

# Object module list for xfpt

SDOBJ = dot.o error.o globals.o literal.o misc.o para.o read.o tree.o xfpt.o

# Link step

xfpt :         $(SDOBJ)
	       @echo "$(CC) -o xfpt"
	       $(FE)$(CC) $(LFLAGS) $(EFENCE) -o xfpt $(SDOBJ)
	       @echo ">>> xfpt command built"; echo ""

# Dependencies

dot.o:         $(DEP) dot.c
error.o:       $(DEP) error.c
globals.o:     $(DEP) globals.c
literal.o:     $(DEP) literal.c
misc.o:        $(DEP) misc.c
para.o:        $(DEP) para.c
read.o:        $(DEP) read.c
tree.o:        $(DEP) tree.c
xfpt.o:        $(DEP) xfpt.c

# Clean up etc

clean:;       /bin/rm -f *.o

# End
