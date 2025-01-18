PREFIX = /usr/local
CC = gcc

ifeq (DEBUG, 1)
STRIP = echo "No stripping..."
CFLAGS = -gdwarf-5 -O0 -arch arm64 -arch x86_64
LDFLAGS = -gdwarf-5 -O0 -arch arm64 -arch x86_64
DSYMUTIL = dsymutil
else
STRIP = strip
CFLAGS = -arch arm64 -arch x86_64 -Os
LDFLAGS = -arch arm64 -arch x86_64
DSYMUTIL = echo "No Debug symbols utility pass..."
endif

CODESIGN = codesign
INSTALL = install
CSIDENT = "Apple Development"
TE2PE_IDENT = com.AnV.Software.TE2PE
PE2TE_IDENT = com.AnV.Software.PE2TE
DEL = rm -Rf
all: PE2TE TE2PE

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

PE2TE: PE2TE.o
	$(CC) $(CFLAGS) -o $@ $^
	$(DSYMUTIL) -f -o $@.dSYM $@
	$(STRIP) $@
	$(CODESIGN) -i $(PE2TE_IDENT) -s $(CSIDENT) $@

TE2PE: TE2PE.o
	$(CC) $(CFLAGS) -o $@ $^
	$(DSYMUTIL) -f -o $@.dSYM $@
	$(STRIP) $@
	$(CODESIGN) -i $(TE2PE_IDENT) -s $(CSIDENT) $@

install: PE2TE TE2PE
	$(INSTALL) -m 755 PE2TE $(PREFIX)/bin
	$(INSTALL) -m 755 TE2PE $(PREFIX)/bin

clean:
	$(DEL) PE2TE TE2PE PE2TE.o TE2PE.o
	$(DEL) *.dSYM
