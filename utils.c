/* Copyright (C) 2026 by Howard Chu.
 * http://www.highlandsun.com/hyc/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* miscellaneous helpers */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"

void randString(myval *mv, myval *charset)
{
	int i;
	char *ptr = mv->mv_val;
	char *chr = charset->mv_val;

	for (i=0; i<mv->mv_len; i++)
		ptr[i] = chr[random() % charset->mv_len];
	ptr[i] = '\0';
}

void generatePassword(myval *mv)
{
	char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}|:<>?-=[];,.";
	myval charset = {set, sizeof(set)-1};
	randString(mv, &charset);
}

void generatePin(myval *mv)
{
	char set[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	myval charset = {set, sizeof(set)-1};
	randString(mv, &charset);
}

/* like strcpy, but returns a pointer to trailing NUL of string */
char *strcopy(char *a, const char *b)
{
	if (!a || !b)
		return a;

	while((*a++ = *b++)) ;
	return a-1;
}

char *strncopy(char *a, const char *b, size_t n)
{
	if (!a || !b || !n)
		return a;

	while ((*a++ = *b++) && --n > 0) ;
	if (n)
		a--;
	return a;
}

static cacherec *cacheHead;

static pthread_mutex_t cache_mutex;

void cacheInit()
{
	pthread_mutex_init(&cache_mutex, NULL);
}

#define EXPIRY	180	/* remove any records older than 3 minutes */

cacherec *cacheSet(myval *pin, myval *pass, myval *prov, myval *owner)
{
	cacherec *cr;
	unsigned char *ptr;
	int len;

	len = sizeof("{\"pin\":\"") + pin->mv_len;
	len += sizeof(",\"password\":\"") + pass->mv_len;
	len += sizeof(",\"provider\":\"") + prov->mv_len;
	len += sizeof(",\"owner\":\"") + owner->mv_len;
	len += 1;
	cr = malloc(len + 1 + sizeof(cacherec));
	if (!cr)
		return NULL;

	time(&cr->c_time);
	cr->c_text.mv_val = (unsigned char *)(cr+1);
	ptr = strcopy(cr->c_text.mv_val, "{\"pin\":\"");
	cr->c_pin.mv_val = ptr;
	cr->c_pin.mv_len = pin->mv_len;
	ptr = strncopy(ptr, pin->mv_val, pin->mv_len);
	ptr = strcopy(ptr, "\",\"password\":\"");
	cr->c_pass.mv_val = ptr;
	cr->c_pass.mv_len = pass->mv_len;
	ptr = strncopy(ptr, pass->mv_val, pass->mv_len);
	ptr = strcopy(ptr, "\",\"provider\":\"");
	cr->c_provider.mv_val = ptr;
	cr->c_provider.mv_len = prov->mv_len;
	ptr = strncopy(ptr, prov->mv_val, prov->mv_len);
	ptr = strcopy(ptr, "\",\"owner\":\"");
	cr->c_owner.mv_val = ptr;
	cr->c_owner.mv_len = owner->mv_len;
	ptr = strncopy(ptr, owner->mv_val, owner->mv_len);
	ptr = strcopy(ptr, "\"}");
	cr->c_text.mv_len = ptr - cr->c_text.mv_val;
	cr->c_token.mv_val = NULL;
	cr->c_token.mv_len = 0;

	pthread_mutex_lock(&cache_mutex);

	{
		/* purge old records */
		cacherec **ptr;
		for (ptr = &cacheHead; *ptr; ) {
			if (cr->c_time - (*ptr)->c_time > EXPIRY) {
				cacherec *c2 = *ptr;
				*ptr = c2->c_next;
				free(c2->c_token.mv_val);
				free(c2);
			} else {
				ptr = &((*ptr)->c_next);
			}
		}
	}

	cr->c_next = cacheHead;
	cacheHead = cr;
	pthread_mutex_unlock(&cache_mutex);
	return cr;
}

cacherec *cacheGet(myval *pin)
{
	cacherec *cr;

	pthread_mutex_lock(&cache_mutex);
	for (cr = cacheHead; cr; cr=cr->c_next) {
		if (pin->mv_len == cr->c_pin.mv_len && !strncmp(pin->mv_val, cr->c_pin.mv_val, pin->mv_len))
			break;
	}
	pthread_mutex_unlock(&cache_mutex);
	return cr;
}

int cachePutToken(cacherec *cr, myval *token)
{
	char *ptr = malloc(token->mv_len+1);
	if (!ptr)
		return errno;

	memcpy(ptr, token->mv_val, token->mv_len);
	ptr[token->mv_len] = '\0';
	pthread_mutex_lock(&cache_mutex);
	cr->c_token.mv_val = ptr;
	cr->c_token.mv_len = token->mv_len;
	pthread_mutex_unlock(&cache_mutex);
	return 0;
}

void cacheDel(cacherec *cr)
{
	cacherec **ptr;

	for (ptr = &cacheHead; *ptr; ptr = &((*ptr)->c_next)) {
		if (*ptr == cr) {
			*ptr = cr->c_next;
			free(cr->c_token.mv_val);
			free(cr);
			break;
		}
	}
}

#define RIGHT2			0x03
#define RIGHT4			0x0f

static const unsigned char b642nib[0x80] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
};

int
decode_b64_inplace( myval *value )
{
	char	*p, *end, *byte;
	char	nib;

	byte = value->mv_val;
	end = value->mv_val + value->mv_len;

	for ( p = value->mv_val, value->mv_len = 0;
		p < end;
		p += 4, value->mv_len += 3 )
	{
		int i;
		for ( i = 0; i < 4; i++ ) {
			if ( p[i] != '=' && (p[i] & 0x80 ||
			    b642nib[ p[i] & 0x7f ] > 0x3f) ) {
				return( -1 );
			}
		}

		/* first digit */
		nib = b642nib[ p[0] & 0x7f ];
		byte[0] = nib << 2;
		/* second digit */
		nib = b642nib[ p[1] & 0x7f ];
		byte[0] |= nib >> 4;
		byte[1] = (nib & RIGHT4) << 4;
		/* third digit */
		if ( p[2] == '=' ) {
			value->mv_len += 1;
			break;
		}
		nib = b642nib[ p[2] & 0x7f ];
		byte[1] |= nib >> 2;
		byte[2] = (nib & RIGHT2) << 6;
		/* fourth digit */
		if ( p[3] == '=' ) {
			value->mv_len += 2;
			break;
		}
		nib = b642nib[ p[3] & 0x7f ];
		byte[2] |= nib;

		byte += 3;
	}
	value->mv_val[ value->mv_len ] = '\0';

    return 0;
}
