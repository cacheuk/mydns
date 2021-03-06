/**************************************************************************************************
 $Id: data.c,v 1.35 2006/01/18 20:46:46 bboy Exp $

 Copyright (C) 2002-2005  Don Moore <bboy@bboy.net>

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

#include "named.h"

/* Make this nonzero to enable debugging for this source file */
#define	DEBUG_DATA	1

/**************************************************************************************************
 FIND_SOA
 Determine the origin in `fqdn' and return the MYDNS_SOA structure for that zone.
 If `label' is non-NULL, the label part of the fqdn will be copied there.
 If provided, `label' should be at least DNS_MAXNAMELEN bytes.
 **************************************************************************************************/
MYDNS_SOA *find_soa(TASK *t, char *fqdn, /* The FQDN provided; return the SOA for the zone in this FQDN */
char *label /* The label part of `fqdn' that is below the origin will be stored here */
) {
	MYDNS_SOA *soa = (MYDNS_SOA *) NULL;
	register size_t fqdnlen = strlen(fqdn);
	register char *origin, *end;
	int errflag;

#if DEBUG_ENABLED && DEBUG_DATA
	Debug("%s: find_soa(\"%s\", \"%s\")", desctask(t), fqdn, label);
#endif

	end = fqdn + fqdnlen;
	for (origin = fqdn; *origin && !soa; origin++)
		if (origin == fqdn || *origin == '.') {
			if (*origin == '.' && *(origin + 1))
				origin++;

			soa = zone_cache_find(t, 0, NULL, DNS_QTYPE_SOA, origin, end - origin,
					&errflag, NULL);

			if (errflag) {
				dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
				return (NULL);
			}

			/* Get label */
			if (soa && label) {
				register int origin_len = strlen(soa->origin);
				register int len = strlen(fqdn) - origin_len - 1;

				if (origin_len == 1)
					len++;
				if (len < 0)
					len = 0;
				if (len > DNS_MAXNAMELEN)
					len = DNS_MAXNAMELEN;
				memcpy(label, fqdn, len);
				label[len] = '\0';
			}
		}
#if DEBUG_ENABLED && DEBUG_DATA
	if (soa)
	Debug("%s: Found SOA: id=%u origin=[%s] ns=[%s] mbox=[%s]", desctask(t), soa->id, soa->origin, soa->ns, soa->mbox);
#endif
	return (soa);
}
/*--- find_soa() --------------------------------------------------------------------------------*/

/**************************************************************************************************
 FIND_RR
 Look up RR.  Returns NULL if not found.
 **************************************************************************************************/
MYDNS_RR *find_rr(TASK *t, MYDNS_SOA *soa, /* The SOA record for this zone */
dns_qtype_t type, /* The type of record to look for */
char *name /* The name to look for in `zone' */
) {
	int errflag;
	MYDNS_RR *rr;

#if DEBUG_ENABLED && DEBUG_DATA
	Debug("%s: find_rr(%u, \"%s\", %s, \"%s\")",
			desctask(t), soa->id, soa->origin, mydns_qtype_str(type), name);
#endif
	rr = zone_cache_find(t, soa->id, soa->origin, type, name, strlen(name),
			&errflag, soa);

	if (errflag) {
		if (rr)
			mydns_rr_free(rr);
		dnserror(t, DNS_RCODE_SERVFAIL, ERR_DB_ERROR);
		return (NULL);
	}

	if (rr) {
		register MYDNS_RR *r;

		/* If the data is empty, reply with error */
		for (r = rr; r; r = r->next)
			if (!r->data || !r->data[0]) {
				if (rr)
					mydns_rr_free(rr);
				dnserror(t, DNS_RCODE_SERVFAIL, ERR_NAME_FORMAT);
				return (NULL);
			}
	}

#if DEBUG_ENABLED && DEBUG_DATA
	if (rr)
	Debug("%s: Found RR: id=%u name=[%s] type=%s data=[%s]", desctask(t), rr->id, rr->name, mydns_qtype_str(rr->type), rr->data);
#endif
	return (rr);
}
/*--- find_rr() ---------------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
