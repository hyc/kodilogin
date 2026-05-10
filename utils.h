typedef struct myval {
	unsigned char *mv_val;
	size_t mv_len;
} myval;

void generatePassword(myval *mv);

void generatePin(myval *mv);

#define PINLEN	6

typedef struct tokeninfo {
	myval t_text;
} tokeninfo;

typedef struct cacherec {
	struct cacherec *c_next;
	myval c_pin;
	myval c_pass;
	myval c_provider;
	myval c_owner;
	myval c_text;
	tokeninfo *c_tokeninfo;
} cacherec;

void cacheInit();

cacherec *cacheSet(myval *pin, myval *pass, myval *provider, myval *owner);

cacherec *cacheGet(myval *pin);

int decode_b64_inplace(myval *val);
