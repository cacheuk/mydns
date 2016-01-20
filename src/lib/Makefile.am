##
##  $Id: Makefile.am,v 1.26 2005/04/20 16:43:22 bboy Exp $
##

noinst_LIBRARIES		=	libmydns.a
AM_CPPFLAGS					=	@INTLINCLUDE@ @UTILINCLUDE@ @SQLINCLUDE@
noinst_HEADERS			=	bits.h header.h mydns.h
libmydns_a_SOURCES	=	ip.c question.c rr.c soa.c sql.c str.c unencode.c key.c

ctags:
	ctags @UTILDIR@/*.[ch] *.[ch]

##  vi:set ts=3:
