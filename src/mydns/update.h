/**************************************************************************************************
 $Id: update.c,v 1.10 2005/12/18 19:16:41 bboy Exp $

 Copyright (C) 2005  Don Moore <bboy@bboy.net>

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

#ifndef _MYDNS_UPDATE_H
#define _MYDNS_UPDATE_H

typedef struct _update_query_rr {
	char *name_ptr;
	char name[DNS_MAXNAMELEN];
	int name_size;
	dns_qtype_t type;
	dns_class_t class;
	uint32_t ttl;
	uint16_t rdlength;
	char rdata[DNS_MAXPACKETLEN_UDP + 1];
	unsigned int size;
} UQRR;

/* This is the temporary RRset described in RFC 2136, 3.2.3 */
typedef struct _update_temp_rrset {
	char name[DNS_MAXNAMELEN];
	dns_qtype_t type;
	char data[DNS_MAXPACKETLEN_UDP + 1];
	uint32_t aux;

	int checked; /* Have we checked this unique name/type? */
} TMPRR;

typedef struct _update_query {
	/* Zone section */
	char name[DNS_MAXNAMELEN]; /* The zone name */
	int name_size; /* The zone name size */
	dns_qtype_t type; /* Must be DNS_QTYPE_SOA */
	dns_class_t class; /* The zone's class */

	UQRR *PR; /* Prerequisite section RRs */
	int numPR; /* Number of items in 'PR' */

	UQRR *UP; /* Update section RRs */
	int numUP; /* Number of items in 'UP' */

	UQRR *AD; /* Additional data section RRs */
	int numAD; /* Number of items in 'AD' */

	TMPRR **tmprr; /* Temporary RR list for prerequisite */
	int num_tmprr; /* Number of items in "tmprr" */
} UQ;

#endif /* !_MYDNS_UPDATE_H */
/* vi:set ts=3: */
