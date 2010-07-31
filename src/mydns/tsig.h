/**************************************************************************************************
	$Id: tsig.h,v 1.18 2005/04/20 16:49:12 bboy Exp $

	Copyright (C) 2006  Christophe Nowicki <cnowicki@easter-eggs.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at Your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**************************************************************************************************/

#ifndef _MYDNS_TSIG_H
#define _MYDNS_TSIG_H

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define DNS_TSIG_FUDGE                 300
#define HMACMD5_ALGORITHM              "\010hmac-md5\007sig-alg\003reg\003int"
#define HMACMD5_ALGORITHM_LEN          26

typedef struct _tansaction_signature
{
   char        *algorithm_value;
	char			algorithm[DNS_MAXNAMELEN];						/* Algorithm name */
   int         algorithm_size;
   uint64_t    timesigned;
   uint16_t    fudge;
   uint16_t    macsize;
	char			*mac;
   uint16_t    originalid;
   uint16_t    error;
   uint16_t    otherlen;
	char			*other;
} TSIG;

typedef struct _key 
{
	char			name[DNS_MAXNAMELEN];						/* Key name */
	char			algorithm[DNS_MAXNAMELEN];					/* Algorithm name */
   int         size;                                  /* Key size */
	char			public[255];      						   /* Public key */
	char			private[255];      						   /* Private key */
} KEY;

extern unsigned char *base64_decode(unsigned char *, unsigned int);
extern void tsig_dump(unsigned char *, TSIG *);
extern void detach_tsig(unsigned char *, int, UQRR *, TSIG *);
extern KEY *tsig_find_key(unsigned char *, unsigned char *);

#endif /* !_MYDNS_TSIG_H */
/* vi:set ts=3: */
