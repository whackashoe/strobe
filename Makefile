# Strobe (c) 1995-1997 Julian Assange, All rights reserved.
# proff@iq.org || proff@gnu.ai.mit.edu

# Modify the below to suit your filesystem

INSTALLDIR=/usr/local/bin
LIBDIR=/usr/local/lib
MANDIR=/usr/local/man/man1

#CC=cc
CC=gcc

#FLAGS=-O -nointl		# SCO
FLAGS= -O -g -Wall

#LIBS= -lnsl -lsocket		# SYSVR4 / SOLARIS
#LIBS= -lsocket -lmalloc -lc_s	# SCO
LIBS=

ETC_SERVICES=/etc/services

# Don't change anything from this point on.

OBJS=strobe.o
BIN=strobe
MAN=strobe.1
DATA=strobe.services
EXTRA=Makefile INSTALL VERSION HISTORY COPYRIGHT POST strobe.man

DEFS=-DLIB_STROBE_SERVICES='"$(LIBDIR)/$(DATA)"'\
     -DSTROBE_SERVICES='"$(DATA)"'\
     -DETC_SERVICES='"$(ETC_SERVICES)"'

CFLAGS=$(FLAGS) $(DEFS)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LIBS)
$(OBJS):
$(DATA):
$(MAN):
$(INSTALLDIR)/$(BIN): $(BIN)
	-rm -f $(INSTALLDIR)/$(BIN)
	install -m 755 -s $(BIN) $(INSTALLDIR)/$(BIN)
$(LIBDIR)/$(DATA): $(DATA)
	-rm -f $(LIBDIR)/$(DATA)
	install -m 644 $(DATA) $(LIBDIR)/$(DATA)
$(MANDIR)/$(MAN): $(MAN)
	-rm -f $(MANDIR)/$(MAN)
	install -m 644 $(MAN) $(MANDIR)/$(MAN)
install: $(INSTALLDIR)/$(BIN) $(LIBDIR)/$(DATA) $(MANDIR)/$(MAN)
strobe.man : $(MAN)
	 nroff -man -Tascii $(MAN) > strobe.man
tar:
	(cd .. ; tar -zcf strobe.tgz strobe)
shar:
	shar -L 50 -o strobe.shar *.c *.1 $(EXTRA) $(DATA)
clean:
	rm -f $(BIN) *.o *.bak *.\~ errlist *.shar.* *.tgz *.swp core
