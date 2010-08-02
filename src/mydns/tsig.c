/**************************************************************************************************
	$Id: tsig.c,v 1.10 2005/12/18 19:16:41 bboy Exp $
	tsig.c: Code to implement RFC 2847 (Secret Key Transaction Authentication for DNS - TSIG)

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

#include "named.h"

#define	DEBUG_TSIG	1

#define	DEBUG_TSIG_SQL	0

#if DEBUG_ENABLED && DEBUG_TSIG
/**************************************************************************************************
	TSIG_DUMP
**************************************************************************************************/
void
tsig_dump(char *desctask, TSIG *s)
{
	Debug("%s: TSIG DUMP: algorithm=[%s] timesigned=[%lld] fudge=[%d] macsize=[%d] mac=[%s] originalid=[%d] error=[%d] otherlen=[%d] other=[%s]",
           desctask,
           s->algorithm, 
           s->timesigned, 
           s->fudge, 
           s->macsize, 
           hex((char *)s->mac, s->macsize),
           s->originalid, 
           s->error, 
           s->otherlen,
           hex((char *)s->other, s->otherlen)
    );
}
/*--- tsig_dump() ---------------------------------------------------------------------------*/

#endif /* DEBUG_ENABLED && DEBUG_UPDATE */

/**************************************************************************************************
	DETACH_TSIG
**************************************************************************************************/
void
detach_tsig(char *query, int len, UQRR *rr, TSIG *tsig) {
   char *start = rr->rdata;
   char *src = rr->rdata;
   int n;

   tsig->algorithm_value = start;
   src = name_unencode(query, len, src, tsig->algorithm, DNS_MAXNAMELEN);
   tsig->algorithm_size = src - start;
   DNS_GET48(tsig->timesigned, src);
   DNS_GET16(tsig->fudge, src);
   DNS_GET16(tsig->macsize, src);

   if (!(tsig->mac = calloc(tsig->macsize, sizeof(char))))
      Err(_("out of memory"));
   memcpy(tsig->mac, src, tsig->macsize);
   src += tsig->macsize;

   DNS_GET16(tsig->originalid, src);
   DNS_GET16(tsig->error, src);
   DNS_GET16(tsig->otherlen, src);

   if (tsig->otherlen > 0) 
   {
    if (!(tsig->other = calloc(tsig->otherlen, sizeof(char))))
      Err(_("out of memory"));
    memcpy(tsig->other, src, tsig->otherlen);
   }

   /* Decrement the additional field counter */
   unsigned short val;
   query += DNS_HEADERSIZE - SIZE16;
   DNS_GET16(val, query);
   query -= SIZE16;
   DNS_PUT16(query, --val);
}



/*--- detach_tsig() ---------------------------------------------------------------------------*/

/**************************************************************************************************
	BASE64_DECODE
	Decode base 64 encoded message
**************************************************************************************************/
unsigned char *base64_decode(unsigned char *buffer, unsigned int len) {
      unsigned char *ret = (unsigned char *) malloc ((((len+2)/3)*4)+1);

      if (!ret)
        Err(_("out of memory"));

      EVP_DecodeBlock (ret, buffer, len);
      ret[(((len+2)/3)*4)] = 0;
      return ret;
}
/*--- base64_decode() ---------------------------------------------------------------------------*/


/**************************************************************************************************
   FIND_KEY	
   Fetch the key from the database
**************************************************************************************************/
KEY *
tsig_find_key(char *desctask, char *keyname)
{
   SQL_RES	*res = NULL;
	SQL_ROW	row;
	char		query[512];
	size_t	querylen;
   KEY      *key;

#if DEBUG_ENABLED && DEBUG_UPDATE
	Debug("%s: DNS UPDATE: find_key: does key [%s] exists?", desctask, keyname);
#endif

	querylen = snprintf(query, sizeof(query),
		"SELECT name,algorithm,size,type,public,private FROM %s WHERE name='%s' LIMIT 1",
		mydns_key_table_name, keyname);

#if DEBUG_TSIG_SQL
	Verbose("%s: DNS UPDATE: %s", desctask, query);
#endif

   if (!(res = sql_query(sql, query, querylen)))
	{
		WarnSQL(sql, "%s: %s", desctask, _("error searching key"));
		return(NULL);
	}
   
   if (sql_num_rows(res) != 1) {
       sql_free(res);
       return(NULL);
   }

   if (!(key = malloc(sizeof(KEY))))
    Err(_("out of memory"));

	if ((row = sql_getrow(res))) {
       strncpy(key->name, row[0], DNS_MAXNAMELEN); 
       strncpy(key->algorithm, row[1], DNS_MAXNAMELEN); 
       key->size = atoi(row[2]); 
       strncpy(key->public, row[3], 255); 
       strncpy(key->private, row[4], 255); 
   }
   sql_free(res);

#if DEBUG_ENABLED && DEBUG_TSIG
	Debug("%s: DNS TSIG: key [%s] algorithm [%s] size [%d]", 
           desctask, keyname, key->algorithm, key->size);
#endif
   return (key);
}
/*--- find_key() ---------------------------------------------------------------------------*/

