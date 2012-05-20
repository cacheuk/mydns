/**************************************************************************************************
 $Id: reply.c,v 1.65 2006/01/18 20:46:47 bboy Exp $

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
#define	DEBUG_REPLY	1

#if DEBUG_ENABLED && DEBUG_REPLY
/* Strings describing the datasections */
char *reply_datasection_str[] = {"QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"};
#endif

/**************************************************************************************************
 REPLY_INIT
 Examines the question data, storing the name offsets (from DNS_HEADERSIZE) for compression.
 **************************************************************************************************/
int reply_init(TASK *t) {
	register char *c; /* Current character in name */

	/* Examine question data, save labels found therein. The question data should begin with
	 the name we've already parsed into t->qname.  I believe it is safe to assume that no
	 compression will be possible in the question. */
	for (c = t->qname; *c; c++)
		if ((c == t->qname || *c == '.') && c[1])
			if (name_remember(t, (c == t->qname) ? c : (c + 1),
					(((c == t->qname) ? c : (c + 1)) - t->qname) + DNS_HEADERSIZE)
					< -1)
				return (-1);
	return (0);
}
/*--- reply_init() ------------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_ADDITIONAL
 Add ADDITIONAL for each item in the provided list.
 **************************************************************************************************/
static void reply_add_additional(TASK *t, RRLIST *rrlist, datasection_t section) {
	register RR *p;

	if (!rrlist)
		return;

	/* Examine each RR in the rrlist */
	for (p = rrlist->head; p; p = p->next) {
		if (p->rrtype == DNS_RRTYPE_RR) {
			MYDNS_RR *rr = (MYDNS_RR *) p->rr;
			if (rr->type == DNS_QTYPE_NS || rr->type == DNS_QTYPE_MX
					|| rr->type == DNS_QTYPE_SRV) {
#if DEBUG_ENABLED && DEBUG_REPLY
				Debug("%s: resolving `%s' (A) for ADDITIONAL data", desctask(t), rr->data);
#endif
				(void) resolve(t, ADDITIONAL, DNS_QTYPE_A, rr->data, 0);
				(void) resolve(t, ADDITIONAL, DNS_QTYPE_AAAA, rr->data, 0);
			} else if (rr->type == DNS_QTYPE_CNAME) {
#if DEBUG_ENABLED && DEBUG_REPLY
				Debug("%s: resolving `%s' (CNAME) for ADDITIONAL data", desctask(t), rr->data);
#endif
				/* Don't do this */
				(void) resolve(t, ADDITIONAL, DNS_QTYPE_CNAME, rr->data, 0);
			}
		}
		t->sort_level++;
	}
}
/*--- reply_add_additional() --------------------------------------------------------------------*/

/**************************************************************************************************
 RDATA_ENLARGE
 Expands t->rdata by `size' bytes.  Returns a pointer to the destination.
 **************************************************************************************************/
static inline char *rdata_enlarge(TASK *t, size_t size) {
	if (!size)
		return (NULL);

	t->rdlen += size;
	if (!t->rdata) {
		if (!(t->rdata = malloc(t->rdlen)))
			Err(_("out of memory"));
	} else {
		if (!(t->rdata = realloc(t->rdata, t->rdlen)))
			Err(_("out of memory"));
	}
	return (t->rdata + t->rdlen - size);
}
/*--- rdata_enlarge() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_START_RR
 Begins an RR.  Appends to t->rdata all the header fields prior to rdlength.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_start_rr(TASK *t, RR *r, char *name, dns_qtype_t type,
		uint32_t ttl, char *desc) {
	char enc[DNS_MAXNAMELEN + 1];
	char *dest;
	int enclen;

	/* name_encode returns dnserror() */
	if ((enclen = name_encode(t, enc, name, t->replylen + t->rdlen, 1)) < 0)
		return rr_error(r->id, "rr %u: %s (%s %s) (name=\"%s\")", r->id,
				_("invalid name in \"name\""), desc, _("record"), name);

	r->length = enclen + SIZE16 + SIZE16 + SIZE32;

	if (!(dest = rdata_enlarge(t, r->length)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	r->offset = dest - t->rdata + DNS_HEADERSIZE + t->qdlen;

	DNS_PUT(dest, enc, enclen);
	DNS_PUT16(dest, type);
#if STATUS_ENABLED
	if (r->rrtype == DNS_RRTYPE_RR && r->rr)
	DNS_PUT16(dest, ((MYDNS_RR *)(r->rr))->class)
	else
#endif
	DNS_PUT16(dest, DNS_CLASS_IN);
	DNS_PUT32(dest, ttl);
	return (0);
}
/*--- reply_start_rr() --------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_GENERIC_RR
 Adds a generic resource record whose sole piece of data is a domain-name,
 or a 16-bit value plus a domain-name.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_generic_rr(TASK *t, RR *r, char *desc) {
	char enc[DNS_MAXNAMELEN + 1], *dest;
	int size, enclen;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN %s `%s'", desctask(t), r->name, mydns_qtype_str(rr->type), rr->data);
#endif

	if (reply_start_rr(t, r, r->name, rr->type, rr->ttl, desc) < 0)
		return (-1);

	if ((enclen = name_encode(t, enc, rr->data, CUROFFSET(t), 1)) < 0)
		return rr_error(r->id, "rr %u: %s (%s) (data=\"%s\")", r->id,
				_("invalid name in \"data\""), desc, rr->data);

	size = enclen;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT(dest, enc, enclen);
	return (0);
}
/*--- reply_add_generic_rr() --------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_A
 Adds an A record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_a(TASK *t, RR *r) {
	char *dest;
	int size;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	struct in_addr addr;
	uint32_t ip;

	if (inet_pton(AF_INET, rr->data, (void *) &addr) <= 0) {
		dnserror(t, DNS_RCODE_SERVFAIL, ERR_INVALID_ADDRESS);
		return rr_error(r->id, "rr %u: %s (A %s) (address=\"%s\")", r->id,
				_("invalid address in \"data\""), _("record"), rr->data);
	}
	ip = ntohl(addr.s_addr);

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN A %s", desctask(t), r->name, inet_ntoa(addr));
#endif
	if (reply_start_rr(t, r, r->name, DNS_QTYPE_A, rr->ttl, "A") < 0)
		return (-1);

	size = SIZE32;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT32(dest, ip);

	return (0);
}
/*--- reply_add_a() -----------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_AAAA
 Adds an AAAA record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_aaaa(TASK *t, RR *r) {
	char *dest;
	int size;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	uint8_t addr[16];

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN AAAA %s", desctask(t), r->name, rr->data);
#endif

	if (inet_pton(AF_INET6, rr->data, (void *) &addr) <= 0) {
		dnserror(t, DNS_RCODE_SERVFAIL, ERR_INVALID_ADDRESS);
		return rr_error(r->id, "rr %u: %s (AAAA %s) (address=\"%s\")", r->id,
				_("invalid address in \"data\""), _("record"), rr->data);
	}

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_AAAA, rr->ttl, "AAAA") < 0)
		return (-1);

	size = sizeof(uint8_t) * 16;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	memcpy(dest, &addr, size);
	dest += size;

	return (0);
}
/*--- reply_add_aaaa() --------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_HINFO
 Adds an HINFO record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_hinfo(TASK *t, RR *r) {
	char *dest;
	size_t oslen, cpulen;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	char os[DNS_MAXNAMELEN + 1] = "", cpu[DNS_MAXNAMELEN + 1] = "";

	if (hinfo_parse(rr->data, cpu, os, DNS_MAXNAMELEN) < 0) {
		dnserror(t, DNS_RCODE_SERVFAIL, ERR_RR_NAME_TOO_LONG);
		return rr_error(r->id, "rr %u: %s (HINFO %s) (data=\"%s\")", r->id,
				_("name too long in \"data\""), _("record"), rr->data);
	}

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN HINFO `%s %s'", desctask(t), r->name, cpu, os);
#endif
	cpulen = strlen(cpu);
	oslen = strlen(os);

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_HINFO, rr->ttl, "HINFO") < 0)
		return (-1);

	r->length += SIZE16 + cpulen + oslen + 2;

	if (!(dest = rdata_enlarge(t, SIZE16 + cpulen + SIZE16 + oslen)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, cpulen + oslen + 2);

	*dest++ = cpulen;
	memcpy(dest, cpu, cpulen);
	dest += cpulen;

	*dest++ = oslen;
	memcpy(dest, os, oslen);
	dest += oslen;

	return (0);
}
/*--- reply_add_hinfo() -------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_MX
 Adds an MX record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_mx(TASK *t, RR *r) {
	char enc[DNS_MAXNAMELEN + 1], *dest;
	int size, enclen;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN MX `%u %s'", desctask(t), r->name, (uint16_t)rr->aux, rr->data);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_MX, rr->ttl, "MX") < 0)
		return (-1);

	if ((enclen = name_encode(t, enc, rr->data, CUROFFSET(t) + SIZE16, 1)) < 0)
		return rr_error(r->id, "rr %u: %s (MX %s) (data=\"%s\")", r->id,
				_("invalid name in \"data\""), _("record"), rr->data);

	size = SIZE16 + enclen;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT16(dest, (uint16_t)rr->aux);
	DNS_PUT(dest, enc, enclen);
	return (0);
}
/*--- reply_add_mx() ----------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_NAPTR
 Adds an NAPTR record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_naptr(TASK *t, RR *r) {
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	size_t flags_len, service_len, regex_len;
	char enc[DNS_MAXNAMELEN + 1], *dest;
	int size, enclen, offset;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN NAPTR `%u %u \"%s\" \"%s\" \"%s\" \"%s\"'", desctask(t),
			r->name, rr->naptr_order, rr->naptr_pref, rr->naptr_flags, rr->naptr_service,
			rr->naptr_regex, rr->naptr_replacement);
#endif

	flags_len = strlen(rr->naptr_flags);
	service_len = strlen(rr->naptr_service);
	regex_len = strlen(rr->naptr_regex);

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_NAPTR, rr->ttl, "NAPTR") < 0)
		return (-1);

	/* We are going to write "something else" and then a name, just like an MX record or something.
	 In this case, though, the "something else" is lots of data.  Calculate the size of
	 "something else" in 'offset' */
	offset = SIZE16 + SIZE16 + 1 + flags_len + 1 + service_len + 1 + regex_len;

	/* Encode the name at the offset */
	if ((enclen = name_encode(t, enc, rr->naptr_replacement,
			CUROFFSET(t) + offset, 1)) < 0)
		return rr_error(r->id, "rr %u: %s (NAPTR %s) (%s=\"%s\")", r->id,
				_("invalid name in \"replacement\""), _("record"),
				_("replacement"), rr->naptr_replacement);

	size = offset + enclen;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT16(dest, (uint16_t)rr->naptr_order);
	DNS_PUT16(dest, (uint16_t)rr->naptr_pref);

	*dest++ = flags_len;
	memcpy(dest, rr->naptr_flags, flags_len);
	dest += flags_len;

	*dest++ = service_len;
	memcpy(dest, rr->naptr_service, service_len);
	dest += service_len;

	*dest++ = regex_len;
	memcpy(dest, rr->naptr_regex, regex_len);
	dest += regex_len;

	DNS_PUT(dest, enc, enclen);

	return (0);
}
/*--- reply_add_naptr() -------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_RP
 Adds an RP record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_rp(TASK *t, RR *r) {
	char *mbox, *txt, *dest;
	char encmbox[DNS_MAXNAMELEN + 1], enctxt[DNS_MAXNAMELEN + 1];
	int size, mboxlen, txtlen;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

	mbox = rr->data;
	txt = rr->rp_txt;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN RP `%s %s'", desctask(t), r->name, mbox, txt);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_RP, rr->ttl, "RP") < 0)
		return (-1);

	if ((mboxlen = name_encode(t, encmbox, mbox, CUROFFSET(t), 1)) < 0)
		return rr_error(r->id, "rr %u: %s (RP %s) (mbox=\"%s\")", r->id,
				_("invalid name in \"mbox\""), _("record"), mbox);

	if ((txtlen = name_encode(t, enctxt, txt, CUROFFSET(t) + mboxlen, 1)) < 0)
		return rr_error(r->id, "rr %u: %s (RP %s) (txt=\"%s\")", r->id,
				_("invalid name in \"txt\""), _("record"), txt);

	size = mboxlen + txtlen;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT(dest, encmbox, mboxlen);
	DNS_PUT(dest, enctxt, txtlen);
	return (0);
}
/*--- reply_add_rp() ----------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_SOA
 Add a SOA record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_soa(TASK *t, RR *r) {
	char *dest, ns[DNS_MAXNAMELEN + 1], mbox[DNS_MAXNAMELEN + 1];
	int size, nslen, mboxlen;
	MYDNS_SOA *soa = (MYDNS_SOA *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN SOA (mbox=[%s])", desctask(t), soa->origin, soa->mbox);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_SOA, soa->ttl, "SOA") < 0)
		return (-1);

	if ((nslen = name_encode(t, ns, soa->ns, CUROFFSET(t), 1)) < 0)
		return rr_error(r->id, "rr %u: %s (SOA %s) (ns=\"%s\")", r->id,
				_("invalid name in \"ns\""), _("record"), soa->ns);

	if ((mboxlen = name_encode(t, mbox, soa->mbox, CUROFFSET(t) + nslen, 1)) < 0)
		return rr_error(r->id, "rr %u: %s (SOA %s) (mbox=\"%s\")", r->id,
				_("invalid name in \"mbox\""), _("record"), soa->mbox);

	size = nslen + mboxlen + (SIZE32 * 5);
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT(dest, ns, nslen);
	DNS_PUT(dest, mbox, mboxlen);
	DNS_PUT32(dest, soa->serial);
	DNS_PUT32(dest, soa->refresh);
	DNS_PUT32(dest, soa->retry);
	DNS_PUT32(dest, soa->expire);
	DNS_PUT32(dest, soa->minimum);
	return (0);
}
/*--- reply_add_soa() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_SRV
 Adds a SRV record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_srv(TASK *t, RR *r) {
	char enc[DNS_MAXNAMELEN + 1], *dest;
	int size, enclen;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN SRV `%u %u %u %s'",
			desctask(t), r->name, (uint16_t)rr->aux, rr->srv_weight, rr->srv_port, rr->data);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_SRV, rr->ttl, "SRV") < 0)
		return (-1);

	/* RFC 2782 says that we can't use name compression on this field... */
	/* Arnt Gulbrandsen advises against using compression in the SRV target, although
	 most clients should support it */
	if ((enclen = name_encode(t, enc, rr->data,
			CUROFFSET(t) + SIZE16 + SIZE16 + SIZE16, 0)) < 0)
		return rr_error(r->id, "rr %u: %s (SRV %s) (data=\"%s\")", r->id,
				_("invalid name in \"data\""), _("record"), rr->data);

	size = SIZE16 + SIZE16 + SIZE16 + enclen;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	DNS_PUT16(dest, (uint16_t)rr->aux);
	DNS_PUT16(dest, (uint16_t)rr->srv_weight);
	DNS_PUT16(dest, (uint16_t)rr->srv_port);
	DNS_PUT(dest, enc, enclen);
	return (0);
}
/*--- reply_add_srv() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_TXT
 Adds a TXT record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_txt(TASK *t, RR *r) {
	char *dest, *src;
	uint16_t size, numstrs, copylen;
	size_t len;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN TXT", desctask(t), r->name);
#endif
	len = strlen(rr->data);

	if (reply_start_rr(t, r, (char *) r->name, DNS_QTYPE_TXT, rr->ttl, "TXT")
			< 0)
		return (-1);

	src = rr->data;
	numstrs = (len / 255) + 1;
	size = len + numstrs;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	while (numstrs--) {
		if (len > 255)
			copylen = 255;
		else
			copylen = len;

		*dest++ = copylen;
		DNS_PUT(dest, src, copylen);
		src += copylen;
		len -= copylen;
	}
	return (0);
}
/*--- reply_add_txt() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_SPF
 Adds a SPF record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_spf(TASK *t, RR *r) {
	char *dest, *src;
	uint16_t size, numstrs, copylen;
	size_t len;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN SPF", desctask(t), r->name);
#endif
	len = strlen(rr->data);

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_SPF, rr->ttl, "SPF") < 0)
		return (-1);

	src = rr->data;
	numstrs = (len / 255) + 1;
	size = len + numstrs;
	r->length += SIZE16 + size;

	if (!(dest = rdata_enlarge(t, SIZE16 + size)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	while (numstrs--) {
		if (len > 255)
			copylen = 255;
		else
			copylen = len;

		*dest++ = copylen;
		DNS_PUT(dest, src, copylen);
		src += copylen;
		len -= copylen;
	}
	return (0);
}
/*--- reply_add_spf() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_SPF
 Adds a SPF record to the reply.
 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_sshfp(TASK *t, RR *r) {
	char *dest, *src;
	uint16_t size, numstrs, copylen;
	size_t len;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN SSHFP", desctask(t), r->name);
#endif
	len = rr->sshfp_size;

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_SSHFP, rr->ttl, "SSHFP") < 0)
		return (-1);

	src = rr->data;

	if (!(dest = rdata_enlarge(t, len + 4)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, len + 2);
	*(dest++) = rr->sshfp_algorithm;
	*(dest++) = rr->sshfp_type;
	DNS_PUT(dest, src, len);

	printf(
			"sshfp: sshfp_size=%d  len=%zu  rr->sshfp_algorithm=%d  rr->sshfp_type=%d key=%40s\n",
			rr->sshfp_size, len, rr->sshfp_algorithm, rr->sshfp_type, rr->data);

	return (0);
}
/*--- reply_add_sshfp() ---------------------------------------------------------------------------*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#define Assert(Cond) if (!(Cond)) abort()

static const char Base64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

/*
 * (From RFC1521 and draft-ietf-dnssec-secext-03.txt)
 * The following encoding technique is taken from RFC 1521 by Borenstein
 * and Freed.  It is reproduced here in a slightly edited form for
 * convenience.
 * 
 * A 65-character subset of US-ASCII is used, enabling 6 bits to be
 * represented per printable character. (The extra 65th character, "=",
 * is used to signify a special processing function.)
 * 
 * The encoding process represents 24-bit groups of input bits as output
 * strings of 4 encoded characters. Proceeding from left to right, a
 * 24-bit input group is formed by concatenating 3 8-bit input groups.
 * These 24 bits are then treated as 4 concatenated 6-bit groups, each
 * of which is translated into a single digit in the base64 alphabet.
 * 
 * Each 6-bit group is used as an index into an array of 64 printable
 * characters. The character referenced by the index is placed in the
 * output string.
 * 
 * Table 1: The Base64 Alphabet
 * 
 * Value Encoding  Value Encoding  Value Encoding  Value Encoding
 * 0 A            17 R            34 i            51 z
 * 1 B            18 S            35 j            52 0
 * 2 C            19 T            36 k            53 1
 * 3 D            20 U            37 l            54 2
 * 4 E            21 V            38 m            55 3
 * 5 F            22 W            39 n            56 4
 * 6 G            23 X            40 o            57 5
 * 7 H            24 Y            41 p            58 6
 * 8 I            25 Z            42 q            59 7
 * 9 J            26 a            43 r            60 8
 * 10 K            27 b            44 s            61 9
 * 11 L            28 c            45 t            62 +
 * 12 M            29 d            46 u            63 /
 * 13 N            30 e            47 v
 * 14 O            31 f            48 w         (pad) =
 * 15 P            32 g            49 x
 * 16 Q            33 h            50 y
 * 
 * Special processing is performed if fewer than 24 bits are available
 * at the end of the data being encoded.  A full encoding quantum is
 * always completed at the end of a quantity.  When fewer than 24 input
 * bits are available in an input group, zero bits are added (on the
 * right) to form an integral number of 6-bit groups.  Padding at the
 * end of the data is performed using the '=' character.
 * 
 * Since all base64 input is an integral number of octets, only the
 * -------------------------------------------------                       
 * following cases can arise:
 * 
 * (1) the final quantum of encoding input is an integral
 * multiple of 24 bits; here, the final unit of encoded
 * output will be an integral multiple of 4 characters
 * with no "=" padding,
 * (2) the final quantum of encoding input is exactly 8 bits;
 * here, the final unit of encoded output will be two
 * characters followed by two "=" padding characters, or
 * (3) the final quantum of encoding input is exactly 16 bits;
 * here, the final unit of encoded output will be three
 * characters followed by one "=" padding character.
 */

int b64_ntop(u_char const *src, size_t srclength, char *target, size_t targsize) {
	size_t datalength = 0;
	u_char input[3];
	u_char output[4];
	size_t i;

	while (2U < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);
		Assert(output[3] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		target[datalength++] = Base64[output[2]];
		target[datalength++] = Base64[output[3]];
	}

	/*
	 * Now we worry about padding. 
	 */
	if (0U != srclength) {
		/*
		 * Get what's left. 
		 */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		if (srclength == 1U)
			target[datalength++] = Pad64;
		else
			target[datalength++] = Base64[output[2]];
		target[datalength++] = Pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0'; /* Returned value doesn't count \0. */
	return (datalength);
}

/*
 * skips all whitespace anywhere.
 * converts characters, four at a time, starting at (or after)
 * src from base - 64 numbers into three 8 bit bytes in the target area.
 * it returns the number of data bytes stored at the target, or -1 on error.
 */

int b64_pton(const char *src, u_char *target, size_t targsize) {
	int tarindex, state, ch;
	char *pos;

	state = 0;
	tarindex = 0;

	while ((ch = *src++) != '\0') {
		if (isspace(ch)) /* Skip whitespace anywhere. */
			continue;

		if (ch == Pad64)
			break;

		pos = strchr(Base64, ch);
		if (pos == 0) /* A non-base64 character. */
			return (-1);

		switch (state) {
		case 0:
			if (target) {
				if ((size_t) tarindex >= targsize)
					return (-1);
				target[tarindex] = (pos - Base64) << 2;
			}
			state = 1;
			break;
		case 1:
			if (target) {
				if ((size_t) tarindex + 1 >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base64) >> 4;
				target[tarindex + 1] = ((pos - Base64) & 0x0f) << 4;
			}
			tarindex++;
			state = 2;
			break;
		case 2:
			if (target) {
				if ((size_t) tarindex + 1 >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base64) >> 2;
				target[tarindex + 1] = ((pos - Base64) & 0x03) << 6;
			}
			tarindex++;
			state = 3;
			break;
		case 3:
			if (target) {
				if ((size_t) tarindex >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base64);
			}
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) { /* We got a pad char. */
		ch = *src++; /* Skip it, get next. */
		switch (state) {
		case 0: /* Invalid = in first position */
		case 1: /* Invalid = in second position */
			return (-1);

		case 2: /* Valid, means one byte of info */
			/*
			 * Skip any number of spaces. 
			 */
			for ((void) NULL; ch != '\0'; ch = *src++)
				if (!isspace(ch))
					break;
			/*
			 * Make sure there is another trailing = sign. 
			 */
			if (ch != Pad64)
				return (-1);
			ch = *src++; /* Skip the = */
			/*
			 * Fall through to "single trailing =" case. 
			 */
			/** FALLTHROUGH */

		case 3: /* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void) NULL; ch != '\0'; ch = *src++)
				if (!isspace(ch))
					return (-1);

			/*
			 * Now make sure for cases 2 and 3 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (target && target[tarindex] != 0)
				return (-1);
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}

static inline int reply_add_rrsig(TASK *t, RR *r) {
	char *dest, *src, enc[DNS_MAXNAMELEN + 1];
	uint16_t size, signame_strs, sig_strs, copylen, key_tag;
	size_t signame_len, sig_len;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	char *tmp, *port, *target, *signers_name, *signature;
	int labels, algorithm, original_ttl, enclen;
	int unsigned signature_expiration, signature_inception;
	dns_qtype_t type_covered;
	char dbuf[512];

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN RRSIG", desctask(t), r->name);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_RRSIG, rr->ttl, "RRSIG") < 0)
		return (-1);

	target = rr->data;
	type_covered = mydns_rr_get_type(strsep(&target, " \t"));
	printf("type_covered: %d\n", type_covered);

	algorithm = atoi(strsep(&target, " \t"));
	printf("algorithm: %d\n", algorithm);

	labels = atoi(strsep(&target, " \t"));
	printf("labels: %d\n", labels);

	original_ttl = atoi(strsep(&target, " \t"));
	printf("original_ttl: %d\n", original_ttl);

	signature_expiration = atoi(strsep(&target, " \t"));
	printf("signature_expiration: %u\n", signature_expiration);

	signature_inception = atoi(strsep(&target, " \t"));
	key_tag = atoi(strsep(&target, " \t"));
	printf("signature_inception: %u\n", signature_inception);

	signers_name = strsep(&target, " \t");
	printf("signers_name: %s\n", signers_name);

	signature = strsep(&target, " \t");
	printf("signature: %s\n", signature);

	if ((enclen = name_encode(t, enc, signers_name, CUROFFSET(t), 0)) < 0)
		return rr_error(r->id, "rr %u: %s (RRSIG %s) (data=\"%s\")", r->id,
				_("invalid name in \"data\""), _("record"), rr->data);

	signame_len = strlen(signers_name);
	signame_strs = (signame_len / 255) + 1;

	sig_len = strlen(signature);
	printf("sig_len b64 len: %d 0x%x\n", (int) sig_len, (int) sig_len);

	sig_len = b64_pton(signature, (uchar *) dbuf, sizeof(dbuf));
	printf("sig_len bin len: %d 0x%x\n", (int) sig_len, (int) sig_len);

	/* add on rr specific sizes */
	size = enclen + sig_len + SIZE16 + 1 + 1 + SIZE32 + SIZE32 + SIZE32 + SIZE16;

	printf("enclen: %d\n", enclen);
	printf("sig_len: %d\n", (int) sig_len);
	printf("%d\n", (int) CUROFFSET(t));

	r->length += size + SIZE16;

	if (!(dest = rdata_enlarge(t, size + SIZE16)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);

	DNS_PUT16(dest, type_covered);
	*dest++ = (uint8_t) algorithm;
	*dest++ = (uint8_t) labels;

	DNS_PUT32(dest, original_ttl);
	DNS_PUT32(dest, signature_expiration);
	DNS_PUT32(dest, signature_inception);
	DNS_PUT16(dest, key_tag);

	DNS_PUT(dest, enc, enclen);
	DNS_PUT(dest, dbuf, sig_len);

	return (0);
}

static inline int reply_add_nsec(TASK *t, RR *r) {
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN NSEC", desctask(t), r->name);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_NSEC, rr->ttl, "NSEC") < 0)
		return (-1);

	return -1;
}

static inline int reply_add_ds(TASK *t, RR *r) {
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN DS", desctask(t), r->name);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_DS, rr->ttl, "DS") < 0)
		return (-1);

	return -1;
}

/**************************************************************************************************
 REPLY_ADD_DNSKEY

 Returns the numeric offset of the start of this record within the reply, or -1 on error.
 **************************************************************************************************/
static inline int reply_add_dnskey(TASK *t, RR *r) {
	char *dest, *src;
	uint16_t size, numstrs, copylen;
	size_t len;
	MYDNS_RR *rr = (MYDNS_RR *) r->rr;
	char *tmp, *port, *target;
	int flags, protocol, algorithm;
	char dbuf[512];

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: REPLY_ADD: `%s' IN SPF", desctask(t), r->name);
#endif

	if (reply_start_rr(t, r, r->name, DNS_QTYPE_DNSKEY, rr->ttl, "DNSKEY") < 0)
		return (-1);

	target = rr->data;
	flags = atoi(strsep(&target, " \t"));
	protocol = atoi(strsep(&target, " \t"));
	algorithm = atoi(strsep(&target, " \t"));

	printf("flags: %d\nprotocol: %d\nalgorithm: %d\n", flags, protocol,
			algorithm);
	printf("dnskey: %s\n", target);

	len = strlen(target);
	printf("b64 len: %d 0x%x\n", (int) len, (int) len);

	len = b64_pton(target, (uchar *) dbuf, sizeof(dbuf));
	printf("bin len: %d 0x%x\n", (int) len, (int) len);

	src = target;

	/* add on rr specific sizes */
	size = len + SIZE16 + 1 + 1;

	r->length += size + SIZE16;

	if (!(dest = rdata_enlarge(t, size + SIZE16)))
		return dnserror(t, DNS_RCODE_SERVFAIL, ERR_INTERNAL);

	DNS_PUT16(dest, size);
	/* size minus ourself */
	DNS_PUT16(dest, flags);
	*dest++ = (uint8_t) protocol;
	*dest++ = (uint8_t) algorithm;

	DNS_PUT(dest, dbuf, len);

	return (0);
}
/*--- reply_add_dnskey() ---------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_ADD_SIGNATURE
 Add TSIG signaure
 **************************************************************************************************/
static char *reply_add_signature(TASK *t, unsigned char *reply) {
	unsigned char data_[DNS_MAXPACKETLEN_UDP];
	unsigned char *data = data_;
	unsigned char *signature;
	unsigned char *sign;
	unsigned short val;
	unsigned char md[EVP_MAX_MD_SIZE]; /* Digest */
	unsigned int mdlen; /* Digest len */
	const EVP_MD *md5; /* MD5 engine */
	HMAC_CTX ctx; /* HMAC Context */
	TSIG tsig; /* Transaction signature */
	int headerlen, rdatalen;

	tsig.timesigned = time(NULL);
	tsig.fudge = DNS_TSIG_FUDGE;
	tsig.originalid = t->originalid;
	tsig.error = t->tsig_error;
	tsig.macsize = 0;
	tsig.mac = NULL;
	tsig.otherlen = 0;
	tsig.other = NULL;

	md5 = EVP_md5();
	HMAC_Init(&ctx, t->tsig_key, t->tsig_keylen, md5);

	/* Digest the query signature */
	DNS_PUT16(data, t->query_maclen);
	data = data_;
	HMAC_Update(&ctx, data, SIZE16);

	HMAC_Update(&ctx, t->query_mac, t->query_maclen);

	/* Digest the reply */
	HMAC_Update(&ctx, reply, t->replylen);

	/* Digest the keyname */
	HMAC_Update(&ctx, (uchar *) t->tsig_keyname, t->tsig_keynamelen);

	/* Digest the TTL + class */
	DNS_PUT16(data, DNS_QTYPE_ANY);
	DNS_PUT32(data, 0);
	data = data_;
	HMAC_Update(&ctx, data, SIZE16 + SIZE32);

	/* Digest algorithm */
	HMAC_Update(&ctx, (const uchar *) HMACMD5_ALGORITHM, HMACMD5_ALGORITHM_LEN);

	/* Digest timesigned and fudge */
	DNS_PUT48(data, tsig.timesigned);
	DNS_PUT16(data, tsig.fudge);
	data = data_;
	HMAC_Update(&ctx, data, SIZE48 + SIZE16);

	/* Digest error and otherlen */
	DNS_PUT16(data, tsig.error);
	DNS_PUT16(data, tsig.otherlen);
	data = data_;
	HMAC_Update(&ctx, data, SIZE16 + SIZE16);

	if (tsig.otherlen > 0) {
		HMAC_Update(&ctx, tsig.other, tsig.otherlen);
	}

	HMAC_Final(&ctx, md, &mdlen);

	if (t->tsig_error == DNS_RCODE_NOERROR) {
		tsig.mac = md;
		tsig.macsize = mdlen;
#if DEBUG_ENABLED && DEBUG_REPLY
		Debug("%s: TSIG REPLY: digest [%s] size [%d]", desctask(t), hex((char *)md, mdlen), mdlen);
#endif
	}

	/* Increment the additional field counter */
	sign = reply;
	sign += DNS_HEADERSIZE - SIZE16;
	DNS_GET16(val, sign);
	sign -= SIZE16;
	DNS_PUT16(sign, ++val);

	headerlen = t->tsig_keynamelen + (SIZE16 * 2) + SIZE32 + SIZE16;
	rdatalen = HMACMD5_ALGORITHM_LEN + SIZE48 + (SIZE16 * 2) + tsig.macsize
			+ (SIZE16 * 3) + tsig.otherlen;

	/* Construct the reply with the signature */
	signature = sign = malloc(t->replylen + headerlen + rdatalen);
	if (!sign)
		Err(_("out of memory"));

	memcpy(sign, reply, t->replylen);
	free(reply);

	sign += t->replylen;
	t->replylen += headerlen + rdatalen;

	/* Build Signature */
	DNS_PUT(sign, t->tsig_keyname, t->tsig_keynamelen);
	DNS_PUT16(sign, DNS_QTYPE_TSIG);
	DNS_PUT16(sign, DNS_CLASS_ANY);
	DNS_PUT32(sign, 0);
	DNS_PUT16(sign, rdatalen);

	DNS_PUT(sign, HMACMD5_ALGORITHM, HMACMD5_ALGORITHM_LEN);
	DNS_PUT48(sign, tsig.timesigned);
	DNS_PUT16(sign, tsig.fudge);
	DNS_PUT16(sign, tsig.macsize);
	DNS_PUT(sign, tsig.mac, tsig.macsize);
	DNS_PUT16(sign, tsig.originalid);
	DNS_PUT16(sign, tsig.error);
	DNS_PUT16(sign, tsig.otherlen);
	DNS_PUT(sign, tsig.other, tsig.otherlen);

#if DEBUG_ENABLED
	tsig_dump(desctask(t), &tsig);
#endif

	HMAC_CTX_cleanup(&ctx);

	return ((char *) signature);
}

/**************************************************************************************************
 REPLY_PROCESS_RRLIST
 Adds each resource record found in `rrlist' to the reply.
 **************************************************************************************************/
static int reply_process_rrlist(TASK *t, RRLIST *rrlist) {
	register RR *r;

	if (!rrlist)
		return (0);

	for (r = rrlist->head; r; r = r->next) {
		switch (r->rrtype) {
		case DNS_RRTYPE_SOA:
			if (reply_add_soa(t, r) < 0)
				return (-1);
			break;

		case DNS_RRTYPE_RR: {
			MYDNS_RR *rr = (MYDNS_RR *) r->rr;

			if (!rr)
				break;

			switch (rr->type) {
			case DNS_QTYPE_A:
				if (reply_add_a(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_AAAA:
				if (reply_add_aaaa(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_CNAME:
				if (reply_add_generic_rr(t, r, "CNAME") < 0)
					return (-1);
				break;

			case DNS_QTYPE_DNSKEY:
				if (reply_add_dnskey(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_RRSIG:
				if (reply_add_rrsig(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_NSEC:
				if (reply_add_nsec(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_DS:
				if (reply_add_ds(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_HINFO:
				if (reply_add_hinfo(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_MX:
				if (reply_add_mx(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_NAPTR:
				if (reply_add_naptr(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_NS:
				if (reply_add_generic_rr(t, r, "NS") < 0)
					return (-1);
				break;

			case DNS_QTYPE_PTR:
				if (reply_add_generic_rr(t, r, "PTR") < 0)
					return (-1);
				break;

			case DNS_QTYPE_RP:
				if (reply_add_rp(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_SPF:
				if (reply_add_spf(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_SRV:
				if (reply_add_srv(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_SSHFP:
				if (reply_add_sshfp(t, r) < 0)
					return (-1);
				break;

			case DNS_QTYPE_TXT:
				if (reply_add_txt(t, r) < 0)
					return (-1);
				break;

			default:
				Warnx("%s: %s: %s", desctask(t), mydns_qtype_str(rr->type),
						_("unsupported resource record type"));
			}
		}
			break;
		}
	}
	return (0);
}
/*--- reply_process_rrlist() --------------------------------------------------------------------*/

/**************************************************************************************************
 TRUNCATE_RRLIST
 Returns new count of items in this list.
 The TC flag is _not_ set if data was truncated from the ADDITIONAL section.
 **************************************************************************************************/
static int truncate_rrlist(TASK *t, off_t maxpkt, RRLIST *rrlist,
		datasection_t ds) {
	register RR *rr;
	register int recs;
#if DEBUG_ENABLED && DEBUG_REPLY
	int orig_recs = rrlist->size;
#endif

	/* Warn about truncated packets, but only if TCP is not enabled.  Most resolvers will try
	 TCP if a UDP packet is truncated. */
	if (!tcp_enabled)
		Verbose("%s: %s", desctask(t), _("query truncated"));

	recs = rrlist->size;
	for (rr = rrlist->head; rr; rr = rr->next) {
		if (rr->offset + rr->length >= maxpkt) {
			recs--;
			if (ds != ADDITIONAL)
				t->hdr.tc = 1;
		} else
			t->rdlen += rr->length;
	}
#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s section truncated from %d records to %d records",
			reply_datasection_str[ds], orig_recs, recs);
#endif
	return (recs);
}
/*--- truncate_rrlist() -------------------------------------------------------------------------*/

/**************************************************************************************************
 REPLY_CHECK_TRUNCATION
 If this reply would be truncated, removes any RR's that won't fit and sets the truncation flag.
 **************************************************************************************************/
static void reply_check_truncation(TASK *t, int *ancount, int *nscount,
		int *arcount) {
	size_t maxpkt = (
			t->protocol == SOCK_STREAM ? DNS_MAXPACKETLEN_TCP :
					(t->ednslen ? t->ednslen - 11 : DNS_MAXPACKETLEN_UDP));
	size_t maxrd = maxpkt - (DNS_HEADERSIZE + t->qdlen);

	if (t->rdlen <= maxrd)
		return;

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("reply_check_truncation() needs to truncate reply (%zu) to fit packet max (%zu)",
			t->rdlen, maxrd);
#endif

	/* Loop through an/ns/ar sections, truncating as necessary, and updating counts */
	t->rdlen = 0;
	*ancount = truncate_rrlist(t, maxpkt, &t->an, ANSWER);
	*nscount = truncate_rrlist(t, maxpkt, &t->ns, AUTHORITY);
	*arcount = truncate_rrlist(t, maxpkt, &t->ar, ADDITIONAL);
}
/*--- reply_check_truncation() ------------------------------------------------------------------*/

/**************************************************************************************************
 BUILD_CACHE_REPLY
 Builds reply data from cached answer.
 **************************************************************************************************/
void build_cache_reply(TASK *t) {
	char *dest = t->reply;

	DNS_PUT16(dest, t->id);
	/* Query ID */
	DNS_PUT(dest, &t->hdr, SIZE16);
	/* Header */
}
/*--- build_cache_reply() -----------------------------------------------------------------------*/

/**************************************************************************************************
 BUILD_REPLY
 Given a task, constructs the reply data.
 **************************************************************************************************/
void build_reply(TASK *t, int want_additional, int sign) {
	char *dest;
	int ancount, nscount, arcount;

	/* Add data to ADDITIONAL section */
	if (want_additional) {
		reply_add_additional(t, &t->an, ANSWER);
		reply_add_additional(t, &t->ns, AUTHORITY);
	}

	/* Sort records where necessary */
	if (t->an.a_records > 1) /* ANSWER section: Sort A/AAAA records */
		sort_a_recs(t, &t->an, ANSWER);
	if (t->an.mx_records > 1) /* ANSWER section: Sort MX records */
		sort_mx_recs(t, &t->an, ANSWER);
	if (t->an.srv_records > 1) /* ANSWER section: Sort SRV records */
		sort_srv_recs(t, &t->an, ANSWER);
	if (t->ar.a_records > 1) /* AUTHORITY section: Sort A/AAAA records */
		sort_a_recs(t, &t->ar, AUTHORITY);

	/* Build `rdata' containing resource records in ANSWER, AUTHORITY, and ADDITIONAL */
	t->replylen = DNS_HEADERSIZE + t->qdlen + t->rdlen;
	if (reply_process_rrlist(t, &t->an) || reply_process_rrlist(t, &t->ns)
			|| reply_process_rrlist(t, &t->ar)) {
		/* Empty RR lists */
		rrlist_free(&t->an);
		rrlist_free(&t->ns);
		rrlist_free(&t->ar);

		/* Make sure reply is empty */
		t->replylen = 0;
		t->rdlen = 0;
		Free(t->rdata);
	}

	ancount = t->an.size;
	nscount = t->ns.size;
	arcount = t->ar.size;

	/* Verify reply length */
	reply_check_truncation(t, &ancount, &nscount, &arcount);

	/* Make sure header bits are set correctly */
	t->hdr.qr = 1;
	t->hdr.cd = 0;

	/* Construct the reply */
	t->replylen = DNS_HEADERSIZE + t->qdlen + t->rdlen;
	if (t->ednslen) {
		arcount++;
		t->replylen += 11;
	}
	dest = t->reply = malloc(t->replylen);
	if (!t->reply)
		Err(_("out of memory"));

	DNS_PUT16(dest, t->id);
	/* Query ID */
	DNS_PUT(dest, &t->hdr, SIZE16);
	/* Header */
	DNS_PUT16(dest, t->qdcount);
	/* QUESTION count */
	DNS_PUT16(dest, ancount);
	/* ANSWER count */
	DNS_PUT16(dest, nscount);
	/* AUTHORITY count */
	DNS_PUT16(dest, arcount);
	/* ADDITIONAL count */
	if (t->qdlen && t->qd)
		DNS_PUT(dest, t->qd, t->qdlen);
	/* Data for QUESTION section */
	DNS_PUT(dest, t->rdata, t->rdlen);
	/* Resource record data */

	if (t->ednslen) {
		uchar edns[] = { 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00 };
		DNS_PUT(dest, edns, 11);
	}

	if (sign) {
		t->reply = reply_add_signature(t, (uchar *) t->reply);
	}

#if DEBUG_ENABLED && DEBUG_REPLY
	Debug("%s: reply:     id = %u", desctask(t), t->id);
	Debug("%s: reply:     qr = %u (message is a %s)", desctask(t), t->hdr.qr, t->hdr.qr ? "response" : "query");
	Debug("%s: reply: opcode = %u (%s)", desctask(t), t->hdr.opcode, mydns_opcode_str(t->hdr.opcode));
	Debug("%s: reply:     aa = %u (answer %s)", desctask(t), t->hdr.aa, t->hdr.aa ? "is authoritative" : "not authoritative");
	Debug("%s: reply:     tc = %u (message %s)", desctask(t), t->hdr.tc, t->hdr.tc ? "truncated" : "not truncated");
	Debug("%s: reply:     rd = %u (%s)", desctask(t), t->hdr.rd, t->hdr.rd ? "recursion desired" : "no recursion");
	Debug("%s: reply:     ra = %u (recursion %s)", desctask(t), t->hdr.ra, t->hdr.ra ? "available" : "unavailable");
	Debug("%s: reply:  rcode = %u (%s)", desctask(t), t->hdr.rcode, mydns_rcode_str(t->hdr.rcode));
	/* escdata(t->reply, t->replylen); */
#endif
}
/*--- build_reply() -----------------------------------------------------------------------------*/

/* vi:set ts=3: */
/* NEED_PO */
