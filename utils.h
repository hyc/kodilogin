typedef struct myval {
	unsigned char *mv_val;
	size_t mv_len;
} myval;

void generatePassword(myval *mv);

void generatePin(myval *mv);

#define PINLEN	6

typedef struct cacherec {
	struct cacherec *c_next;
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
