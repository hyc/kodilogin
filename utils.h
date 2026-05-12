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

#include <time.h>

typedef struct myval {
	unsigned char *mv_val;
	size_t mv_len;
} myval;

void generatePassword(myval *mv);

void generatePin(myval *mv);

#define PINLEN	6

typedef struct cacherec {
	struct cacherec *c_next;
	time_t c_time;
	myval c_pin;
	myval c_pass;
	myval c_provider;
	myval c_owner;
	myval c_text;
	myval c_token;
} cacherec;

void cacheInit();

cacherec *cacheSet(myval *pin, myval *pass, myval *provider, myval *owner);

cacherec *cacheGet(myval *pin);

int cachePutToken(cacherec *cr, myval *token);

void cacheDel(cacherec *cr);

int decode_b64_inplace(myval *val);

char *strcopy(char *a, const char *b);
char *strncopy(char *a, const char *b, size_t n);
