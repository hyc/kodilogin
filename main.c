/* kodilogin: OAUTH2 helper for Google Drive addon for Kodi.
 * Copyright (C) 2026 by Howard Chu.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#define USE_WINSOCK
#define	sock_err(msg)	fprintf(stderr,"%s error %d\n",msg,WSAGetLastError())
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define	sock_err(msg)	perror(msg)
#endif
#include <string.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "tpool.h"
#include "utils.h"

#define	DEFPORT	3000
#define DEFTHREADS	4

int tcp;
unsigned short port = DEFPORT;
struct sockaddr_in sa;
unsigned char buf[BUFSIZ];
char namebuf[256];
int my_max_thr = DEFTHREADS;

char *CAcertfile;
char *certfile;
char *keyfile;
SSL_CTX *myctx;
SSL_CTX *outctx;

typedef struct client {
	SSL *c_ssl;
	struct in_addr c_addr;
	char c_addrbuf[INET_ADDRSTRLEN+1];
	myval c_addrstr;
	int c_fd;
} client;

#define CODE_OK	"200 OK"
#define CODE_ACCEPTED "202 Accepted"
#define CODE_FOUND "302 Found"
#define CODE_TMPREDIR "307 Temporary Redirect"
#define CODE_BAD_REQUEST "400 Bad Request"
#define CODE_UNAUTHORIZED "401 Unauthorized"
#define CODE_NOT_FOUND "404 Not Found"
#define CODE_INTERNAL "500 Internal Server Error"
#define CODE_UNAVAILABLE "503 Service Unavailable"

char *myname;
struct in_addr myaddr;
myval baseUrl;
myval callbackUrl;
myval successUrl;
myval clientId, clientSecret;

static void usage(char *prog)
{
	fprintf(stderr,
		"usage: %s [-a address] [-h hostFQDN] [-p port] [-C CAcertfile] [-c certfile] [-k keyfile] [-t threads]\n", prog);
	exit(EXIT_FAILURE);
}

void *do_client(void *arg);

typedef int (myrdwr)(client *cp, char *buf, size_t len);
typedef int (myclos)(client *cp);

myrdwr *my_send, *my_recv;
myclos *my_clos;

static int my_ssl_recv(client *cp, char *buf, size_t len) {
	return SSL_read(cp->c_ssl, buf, len);
}

static int my_ssl_send(client *cp, char *buf, size_t len) {
	return SSL_write(cp->c_ssl, buf, len);
}

static int my_ssl_clos(client *cp) {
	while (!SSL_shutdown(cp->c_ssl)) {
		char buf[1024];
		while (SSL_read(cp->c_ssl, buf, sizeof(buf) >= 0))
			;
	}
	return 0;
}

static int my_sok_recv(client *cp, char *buf, size_t len) {
	return recv(cp->c_fd, buf, len, 0);
}

static int my_sok_send(client *cp, char *buf, size_t len) {
	return send(cp->c_fd, buf, len, 0);
}

static int my_sok_clos(client *cp) {
	return close(cp->c_fd);
}

int main( int argc, char *argv[] )
{
	struct sockaddr_in sa2;
	socklen_t salen;
	char *prog = argv[0];
	int i, j;
	int fd;

	/* -a: specific address to bind to, otherwise INADDR_ANY
	 * -h: FQDN to use in URLs
	 * -p: port number to bind to
	 * -C: CA cert file
	 * -c: server cert file
	 * -k: server key file
	 * -t: max threads to use
	 */

	while ((i = getopt(argc, argv, "a:c:h:k:p:t:C:")) != EOF) {
		switch(i) {
		case 'a':
			if (!inet_aton(optarg, &myaddr)) {
				fprintf(stderr, "Invalid address %s\n", optarg);
				exit(1);
			}
			break;
		case 'h':
			myname = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'c':
			certfile = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'C':
			CAcertfile = optarg;
			break;
		case 't':
			my_max_thr = atoi(optarg);
			break;
		default:
			usage(prog);
		}
	}

	clientId.mv_val = getenv("GOOGLE_CLIENT_ID");
	if (!clientId.mv_val) {
		fprintf(stderr, "GOOGLE_CLIENT_ID not set\n");
		exit(1);
	}
	clientId.mv_len = strlen(clientId.mv_val);

	clientSecret.mv_val = getenv("GOOGLE_CLIENT_SECRET");
	if (!clientSecret.mv_val) {
		fprintf(stderr, "GOOGLE_CLIENT_SECRET not set\n");
		exit(1);
	}
	clientSecret.mv_len = strlen(clientSecret.mv_val);

	OPENSSL_init_ssl(0, NULL);
	outctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_default_verify_paths(outctx);

	i = ((CAcertfile != NULL) << 2) | ((certfile != NULL) << 1) | (keyfile != NULL);
	if (i) {
		if (i != 7) {
			fprintf(stderr, "Invalid or incomplete TLS options\n");
			exit(1);
		}
		myctx = SSL_CTX_new(TLS_method());
		if (!SSL_CTX_load_verify_locations(myctx, CAcertfile, NULL)) {
			fprintf(stderr, "Failed to set CAcertfile\n");
			exit(1);
		}
		if (!SSL_CTX_use_certificate_chain_file(myctx, certfile)) {
			fprintf(stderr, "Failed to set certfile\n");
			exit(1);
		}
		if (!SSL_CTX_use_PrivateKey_file(myctx, keyfile, SSL_FILETYPE_PEM)) {
			fprintf(stderr, "Failed to set keyfile \n");
			exit(1);
		}
	}

	{
		unsigned int seed;
		RAND_bytes((unsigned char *)&seed, sizeof(seed));
		srandom(seed);
	}

	if (myctx) {
		my_send = my_ssl_send;
		my_recv = my_ssl_recv;
		my_clos = my_ssl_clos;
	} else {
		my_send = my_sok_send;
		my_recv = my_sok_recv;
		my_clos = my_sok_clos;
	}

	if (!myname) {
		struct addrinfo hints = {0}, *aip;
		if (gethostname(namebuf, sizeof(namebuf))) {
			perror("gethostname");
			exit(1);
		}
		hints.ai_flags = AI_CANONNAME;
		if ((i=getaddrinfo(namebuf, NULL, &hints, &aip))) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(i));
			exit(1);
		}
		if (aip->ai_canonname) {
			myname = strdup(aip->ai_canonname);
		} else {
			myname = namebuf;
		}
		freeaddrinfo(aip);
	}

	i = sizeof("http://:xxxxx/") + strlen(myname);
	if (myctx) i++;
	baseUrl.mv_val = malloc(i+1);
	if (!baseUrl.mv_val) {
		perror("malloc");
		exit(1);
	}
	baseUrl.mv_len = sprintf(baseUrl.mv_val, "http%s://%s:%d/", myctx ? "s" : "", myname, port);

	callbackUrl.mv_val = malloc(baseUrl.mv_len + sizeof("callback"));
	if (!callbackUrl.mv_val) {
		perror("malloc");
		exit(1);
	}
	{
		unsigned char *ptr = strcopy(callbackUrl.mv_val, baseUrl.mv_val);
		ptr = strcopy(ptr, "callback");
		callbackUrl.mv_len = ptr - callbackUrl.mv_val;
	}

	successUrl.mv_val = malloc(baseUrl.mv_len + sizeof("success"));
	if (!successUrl.mv_val) {
		perror("malloc");
		exit(1);
	}
	{
		unsigned char *ptr = strcopy(successUrl.mv_val, baseUrl.mv_val);
		ptr = strcopy(ptr, "success");
		successUrl.mv_len = ptr - successUrl.mv_val;
	}

	if ((tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		sock_err("tcp socket");
		exit(1);
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = myaddr.s_addr;

	tpool_init(my_max_thr);
	cacheInit();

	if (bind(tcp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		sock_err("tcp bind");
		exit(1);
	}
	listen( tcp, 2 );
	salen = sizeof(sa2);
	while((fd = accept(tcp, (struct sockaddr *)&sa2, &salen)) >= 0) {
		client *cp = malloc(sizeof(client));
		cp->c_fd = fd;
		cp->c_addr.s_addr = sa2.sin_addr.s_addr;
		cp->c_addrstr.mv_val = cp->c_addrbuf;
		cp->c_addrstr.mv_len = 0;
		if (myctx) {
			SSL *ssl = SSL_new(myctx);
			BIO *bio = BIO_new_socket(fd, 1);
			SSL_set_bio(ssl, bio, bio);
			cp->c_ssl = ssl;
		} else {
			cp->c_ssl = NULL;
		}
		tpool_submit(do_client, cp);
	}
}

void do_resp(client *cp, char *code, char *mtype, myval *headers, myval *text)
{
	char buf[16384], *pbuf, *ptr;
	int len = text->mv_len;

	if (headers)
		len += headers->mv_len;
	if (len+100 > sizeof(buf)) {
		pbuf = malloc(len+100);
	} else {
		pbuf = buf;
	}
	ptr = pbuf;
	ptr += sprintf(ptr, "HTTP/1.1 %s\r\n", code);
	ptr += sprintf(ptr, "Content-Type: %s\r\n", mtype);
	ptr += sprintf(ptr, "Content-Length: %d\r\n", (int)text->mv_len);
	if (headers)
		ptr = strncopy(ptr, headers->mv_val, headers->mv_len);
	*ptr++ = '\r'; *ptr++ = '\n';
	memcpy(ptr, text->mv_val, text->mv_len);
	ptr += text->mv_len;
	len = ptr - pbuf;
	my_send(cp, pbuf, len);
	if (pbuf != buf)
		free(pbuf);
}

void get_ip(client *cp, unsigned char *ibuf) {
	unsigned char *ptr;

	ptr = strstr(ibuf, "X-Forwarded-For:");
	if (ptr) {
		unsigned char *crnl, *comma;
		ptr += sizeof("X-Forwarded-For:");
		while (!isdigit(*ptr)) ptr++;

		crnl = strchr(ptr, '\r');
		comma = memchr(ptr, ',', crnl-ptr);
		if (comma) crnl = comma;
		cp->c_addrstr.mv_len = crnl - ptr;
		strncopy(cp->c_addrstr.mv_val, ptr, cp->c_addrstr.mv_len);
		return;
	}
	ptr = strstr(ibuf, "X-Real-IP:");
	if (ptr) {
		unsigned char *crnl;
		ptr += sizeof("X-Real-IP:");
		while (!isdigit(*ptr)) ptr++;

		crnl = strchr(ptr, '\r');
		cp->c_addrstr.mv_len = crnl - ptr;
		strncopy(cp->c_addrstr.mv_val, ptr, cp->c_addrstr.mv_len);
		return;
	}
	ptr = strstr(ibuf, "Forwarded: for=");
	if (ptr) {
		unsigned char *crnl;
		ptr += sizeof("Forwarded: for");

		crnl = strchr(ptr, '\r');
		cp->c_addrstr.mv_len = crnl - ptr;
		strncopy(cp->c_addrstr.mv_val, ptr, cp->c_addrstr.mv_len);
		return;
	}
	inet_ntop(AF_INET, &cp->c_addr, cp->c_addrstr.mv_val, INET_ADDRSTRLEN);
	cp->c_addrstr.mv_len = strlen(cp->c_addrstr.mv_val);
	return;
}

void do_authz(client *cp, cacherec *cr);
void do_token(client *cp, cacherec *cr, myval *grant, myval *toktype, myval *token);

void *do_client(void *arg) {
	client *cp = arg;
	unsigned char ibuf[32768], *ptr, *iptr, *iend;
	int num;
	myval resp;

	if (cp->c_ssl) {
		if (!SSL_accept(cp->c_ssl)) {
			fprintf(stderr, "SSL_accept failed\n");
			goto finish;
		}
	}

	iend = ibuf+sizeof(ibuf);
	iptr = ibuf;
	for(;;) {
		num = my_recv(cp, iptr, iend-iptr);
		if (num <= 0)
			break;
		iptr += num;
		*iptr = '\0';
		switch(ibuf[0]) {
		case 'G':
			if (!strncmp(ibuf+1, "ET /ip ", sizeof("ET /ip ")-1)) {
				get_ip(cp, ibuf);
				resp = cp->c_addrstr;
				do_resp(cp, CODE_OK, "text/plain", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /pin/", sizeof("ET /pin/")-1)) {
				/* lookup existing pin */
				myval pinv;
				pinv.mv_val = ibuf+sizeof("GET /pin");
				if (pinv.mv_val[PINLEN] == ' ') {
					cacherec *cr;
					pinv.mv_len = PINLEN;
					cr = cacheGet(&pinv);
					if (cr) {
						get_ip(cp, ibuf);
						ptr = strstr(pinv.mv_val + PINLEN, "Authorization");
						if (ptr && cr->c_owner.mv_len == cp->c_addrstr.mv_len &&
							!strncmp(cr->c_owner.mv_val, cp->c_addrstr.mv_val, cp->c_addrstr.mv_len)) {
							ptr += sizeof("Authorization:");
							if (!strncasecmp(ptr, "Basic ", sizeof("Basic ")-1)) {
								myval cred;
								cred.mv_val = ptr + sizeof("Basic");
								ptr = strchr(cred.mv_val, '\r');
								if (ptr) {
									cred.mv_len = ptr - cred.mv_val;
									if (!decode_b64_inplace(&cred)) {
										myval pass;
										pass.mv_val = strchr(cred.mv_val, ':');
										if (pass.mv_val) {
											pass.mv_val++;
											pass.mv_len = cred.mv_len - (pass.mv_val - cred.mv_val);
											if (pass.mv_len == cr->c_pass.mv_len &&
												!strncmp(pass.mv_val, cr->c_pass.mv_val, pass.mv_len)) {
												if (!cr->c_token.mv_val) {
													resp.mv_val = "";
													resp.mv_len = 0;
													do_resp(cp, CODE_ACCEPTED, "application/json", NULL, &resp);
												} else {
													do_resp(cp, CODE_OK, "application/json", NULL, &cr->c_token);
													cacheDel(cr);
												}
												my_clos(cp);
												break;
											}
										}
									}
								}
							}
						}
					}
				}
				resp.mv_val = "";
				resp.mv_len = 0;
				do_resp(cp, CODE_NOT_FOUND, "text/plain", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET / ", sizeof("ET /"))) {
#define MAINPAGE "<html><head><title>Authenticate Your Kodi</title></head>\n"\
"<body><h1>Authenticate Your Kodi</h1><form action=\"/authorize\">\n"\
"Code: <input name=\"pin\" type=\"text\"><p><input type=\"submit\" value=\"Send\">\n"\
"</form><p><p>This program's source code is at\n"\
"<a href=\"https://github.com/hyc/kodilogin\">https://github.com/hyc/kodilogin</a></body></html>\n"
				resp.mv_val = MAINPAGE;
				resp.mv_len = sizeof(MAINPAGE)-1;
				do_resp(cp, CODE_OK, "text/html", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /authorize?", sizeof("ET /authorize"))) {
				ptr = ibuf+sizeof("ET /authorize?pin=");
				if (ptr[PINLEN] == ' ') {
					cacherec *cr;
					myval pinv;
					pinv.mv_val = ptr;
					pinv.mv_len = PINLEN;
					cr = cacheGet(&pinv);
					get_ip(cp, ibuf);
					if (cr && cr->c_owner.mv_len == cp->c_addrstr.mv_len &&
						!strncmp(cp->c_addrstr.mv_val, cr->c_owner.mv_val, cr->c_owner.mv_len)) {
						do_authz(cp, cr);
						my_clos(cp);
						break;
					}
				}
				resp.mv_val = "Invalid PIN";
				resp.mv_len = sizeof("Invalid PIN")-1;
				do_resp(cp, CODE_UNAUTHORIZED, "text/plain", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /callback?", sizeof("ET /callback"))) {
#define INVALID_REQUEST "Invalid request"
#define INVALID_PIN "Your PIN is no longer valid. Please try again."
#define COULDNT_AUTH "Unable to get authorization from provider. Your account doesn't have a valid drive resource."
#define AUTH_GRANT	"authorization_code"
#define CODE "code"
				myval resp;
				ptr = ibuf + sizeof("ET /callback");
				ptr = strstr(ptr, "state=");
				if (ptr) {
					myval pinv;
					pinv.mv_val = ptr + sizeof("state");
					if (pinv.mv_val[PINLEN] == '&') {
						cacherec *cr;
						pinv.mv_len = PINLEN;
						cr = cacheGet(&pinv);
						if (cr) {
							ptr = strstr(ibuf+sizeof("ET /callback"), CODE "=");
							if (ptr) {
								myval code, grant = {AUTH_GRANT, sizeof(AUTH_GRANT)-1};
								myval toktype = {CODE, sizeof(CODE)-1};
								code.mv_val = ptr + sizeof(CODE);
								ptr = strchr(code.mv_val, '&');
								if (!ptr)
									ptr = strchr(code.mv_val, '\r');
								if (ptr)
									code.mv_len = ptr - code.mv_val;
								else
									code.mv_len = strlen(code.mv_val);
								do_token(cp, cr, &grant, &toktype, &code);
								my_clos(cp);
								break;
							}
						}
					}
					resp.mv_val = INVALID_PIN;
					resp.mv_len = sizeof(INVALID_PIN)-1;
					goto out;
				}
				resp.mv_val = INVALID_REQUEST;
				resp.mv_len = sizeof(INVALID_REQUEST)-1;
out:
				do_resp(cp, CODE_BAD_REQUEST, "text/plain", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /success ", sizeof("ET /success"))) {
#define SUCCESSPAGE "<html><head><title>Authentication Completed</title></head>\n"\
"<body><h1>Authentication Completed</h1>Your authentication has been successful.<p>\n"\
"Now Kodi will complete your login.<p>\n"\
"<a href=\"/\">Home</a></body></html>\n"
				resp.mv_val = SUCCESSPAGE;
				resp.mv_len = sizeof(SUCCESSPAGE)-1;
				do_resp(cp, CODE_OK, "text/html", NULL, &resp);
				my_clos(cp);
			} else {
				resp.mv_val = "";
				resp.mv_len = 0;
				do_resp(cp, CODE_NOT_FOUND, "text/plain", NULL, &resp);
				my_clos(cp);
			}
			break;
		case 'P':
			if (!strncmp(ibuf+1, "OST /pin ", sizeof("OST /pin"))) {
				/* generate new pin */
				unsigned char pinbuf[PINLEN+1], passbuf[129];
				myval pinv = {pinbuf, sizeof(pinbuf)-1};
				myval passv = {passbuf, sizeof(passbuf)-1};
				myval prov, owner;
				cacherec *cr;
				int len;

				get_ip(cp, ibuf);
				owner = cp->c_addrstr;
				prov.mv_val = strstr(ibuf, "provider=");
				if (!prov.mv_val)
					continue;
				prov.mv_val += sizeof("provider");
				prov.mv_len = strlen(prov.mv_val);
				generatePin(&pinv);
				generatePassword(&passv);
				cr = cacheSet(&pinv, &passv, &prov, &owner);
				if (cr)
					do_resp(cp, CODE_OK, "application/json", NULL, &cr->c_text);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "OST /refresh ", sizeof("OST /refresh"))) {
#define REFRESH	"refresh_token"
				myval prov, reftok, grant = {REFRESH, sizeof(REFRESH)-1};
				prov.mv_val = strstr(ibuf, "provider=");
				if (!prov.mv_val)
					continue;
				prov.mv_val += sizeof("provider");
				ptr = strchr(prov.mv_val, '&');
				if (!ptr)
					continue;
				prov.mv_len = ptr - prov.mv_val;
				ptr++;
				if (!strncmp(ptr, REFRESH "=", sizeof(REFRESH))) {
					reftok.mv_val = ptr + sizeof(REFRESH);
					reftok.mv_len = iptr - reftok.mv_val;
					do_token(cp, NULL, &grant, &grant, &reftok);
				}
				my_clos(cp);
			}
			break;
		}
	}

finish:
	free(cp);
	return NULL;
}

#define AUTHZ_URL "Location: https://accounts.google.com/o/oauth2/v2/auth?"
#define CLIENT_ID "client_id="
#define REDIRECT_URI "redirect_uri="
#define STATE "state="
#define RESPONSE_TYPE "response_type=code"
#define SCOPE "scope=https://www.googleapis.com/auth/drive.readonly%20https://www.googleapis.com/auth/drive.photos.readonly%20https://www.googleapis.com/auth/photoslibrary.readonly%20profile"
#define ACCESS_TYPE "access_type=offline"
#define PROMPT "prompt=consent"

void do_authz(client *cp, cacherec *cr)
{
	myval header, resp;
	int len = sizeof(AUTHZ_URL) + sizeof(CLIENT_ID) + sizeof(REDIRECT_URI) +
		sizeof(STATE) + sizeof(RESPONSE_TYPE) + sizeof(SCOPE) +
		sizeof(ACCESS_TYPE) + sizeof(PROMPT) + PINLEN + 2;
	len += clientId.mv_len + callbackUrl.mv_len;

	header.mv_val = malloc(len);
	if (header.mv_val) {
		unsigned char *ptr = header.mv_val;
		ptr = strcopy(ptr, AUTHZ_URL);
		ptr = strcopy(ptr, CLIENT_ID);
		ptr = strcopy(ptr, clientId.mv_val);
		*ptr++ = '&';
		ptr = strcopy(ptr, REDIRECT_URI);
		ptr = strcopy(ptr, callbackUrl.mv_val);
		*ptr++ = '&';
		ptr = strcopy(ptr, STATE);
		ptr = strncopy(ptr, cr->c_pin.mv_val, PINLEN);
		*ptr++ = '&';
		ptr = strcopy(ptr, RESPONSE_TYPE);
		*ptr++ = '&';
		ptr = strcopy(ptr, SCOPE);
		*ptr++ = '&';
		ptr = strcopy(ptr, ACCESS_TYPE);
		*ptr++ = '&';
		ptr = strcopy(ptr, PROMPT);
		*ptr++ = '\r'; *ptr++ = '\n';
		header.mv_len = ptr - header.mv_val;
		resp.mv_val = "";
		resp.mv_len = 0;
		do_resp(cp, CODE_FOUND, "text/plain", &header, &resp);
		free(header.mv_val);
	}
}

#define HNAME "oauth2.googleapis.com"
#define PREQ "POST /token HTTP/1.1\r\n"
#define HOSTH "Host: " HNAME "\r\n"
#define ACCEPT "Accept: */*\r\n"
#define CTYPE "Content-Type: application/x-www-form-urlencoded\r\n"
#define CTLEN "Content-Length: %d\r\n"

#define CLIENT_SECRET "client_secret="
#define GRANT_TYPE "grant_type="
#define REDIRECT "redirect_uri="

void do_token(client *cp, cacherec *cr, myval *grant, myval *toktype, myval *token)
{
	struct addrinfo *ailist, *aip;
	int i, fd, len, clen;
	SSL *ssl;
	myval req, resp;
	unsigned char *ptr, *end, *str;
	unsigned char ibuf[16384];

	if ((i=getaddrinfo(HNAME, "https", NULL, &ailist))) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(i));
		resp.mv_val = "Couldn't resolve " HNAME "'s address";
		resp.mv_len = sizeof("Couldn't resolve " HNAME "'s address") - 1;
		do_resp(cp, CODE_UNAVAILABLE, "text/plain", NULL, &resp);
		return;
	}
	for (aip = ailist; aip; aip=aip->ai_next) {
		if ((fd = socket(aip->ai_family, SOCK_STREAM, 0)) < 0) {
			sock_err("out socket");
			exit(1);
		}
		if (connect(fd, aip->ai_addr, aip->ai_addrlen) >= 0)
			break;

		close(fd);
		sock_err("out connect");
	}
	freeaddrinfo(ailist);
	if (!aip) {
		resp.mv_val = "Couldn't connect to " HNAME;
		resp.mv_len = sizeof("Couldn't connect to " HNAME)-1;
		do_resp(cp, CODE_UNAVAILABLE, "text/plain", NULL, &resp);
		return;
	}

	ssl = SSL_new(outctx);
	if (!ssl) {
		close(fd);
		resp.mv_val = "Couldn't allocate SSL session";
		resp.mv_len = sizeof("Couldn't allocate SSL session")-1;
		do_resp(cp, CODE_INTERNAL, "text/plain", NULL, &resp);
		return;
	} else
	{
		BIO *bio = BIO_new_socket(fd, 1);
		SSL_set_bio(ssl, bio, bio);
	}
	if (SSL_connect(ssl) != 1) {
		SSL_free(ssl);
		resp.mv_val = "SSL handshake failed";
		resp.mv_len = sizeof("SSL handshake failed")-1;
		do_resp(cp, CODE_UNAVAILABLE, "text/plain", NULL, &resp);
		return;
	}
	len = sizeof(PREQ) + sizeof(HOSTH) + sizeof(ACCEPT) + sizeof(CTYPE) + sizeof(CTLEN) + 4;
	clen = sizeof(CLIENT_ID) + sizeof(REDIRECT) + sizeof(CLIENT_SECRET) +
		sizeof(GRANT_TYPE);
	clen += clientId.mv_len + callbackUrl.mv_len + clientSecret.mv_len + grant->mv_len +
		toktype->mv_len + 1 + token->mv_len;
	req.mv_val = malloc(len + clen);
	ptr = strcopy(req.mv_val, PREQ);
	ptr = strcopy(ptr, HOSTH);
	ptr = strcopy(ptr, ACCEPT);
	ptr = strcopy(ptr, CTYPE);
	ptr += sprintf(ptr, CTLEN, clen);
	*ptr++ = '\r'; *ptr++ = '\n';
	ptr = strcopy(ptr, CLIENT_ID);
	ptr = strcopy(ptr, clientId.mv_val);
	*ptr++ = '&';
	ptr = strcopy(ptr, REDIRECT);
	ptr = strcopy(ptr, callbackUrl.mv_val);
	*ptr++ = '&';
	ptr = strcopy(ptr, CLIENT_SECRET);
	ptr = strcopy(ptr, clientSecret.mv_val);
	*ptr++ = '&';
	ptr = strcopy(ptr, GRANT_TYPE);
	ptr = strcopy(ptr, grant->mv_val);
	*ptr++ = '&';
	ptr = strcopy(ptr, toktype->mv_val);
	*ptr++ = '=';
	ptr = strncopy(ptr, token->mv_val, token->mv_len);
	req.mv_len = ptr - req.mv_val;
	len = SSL_write(ssl, req.mv_val, req.mv_len);
	free(req.mv_val);

	ptr = ibuf;
	end = ibuf+sizeof(ibuf);
	for (;;) {
		len = SSL_read(ssl, ptr, end-ptr);
		if (len <= 0)
			break;
		str = strstr(ibuf, "\r\n\r\n");
		ptr += len;
		if (!str || ptr-str < 7)
			continue;
		str += 4;
		if (sscanf(str, "%x", &clen) != 1)
			continue;
		*ptr = '\0';
		str = strchr(str, '\n');
		if (!str)
			continue;
		str++;
		end = str+clen;
		if (ptr-str >= clen)
			break;
	}
	req.mv_val = str;
	req.mv_len = clen;
	if (cr) {
		cachePutToken(cr, &req);
		req.mv_val = ibuf;
		ptr = strcopy(req.mv_val, "Location: ");
		ptr = strcopy(ptr, successUrl.mv_val);
		*ptr++ = '\r'; *ptr++ = '\n';
		req.mv_len = ptr - req.mv_val;
		resp.mv_val = "";
		resp.mv_len = 0;
		do_resp(cp, CODE_TMPREDIR, "text/plain", &req, &resp);
	} else {
		do_resp(cp, CODE_OK, "application/json", NULL, &req);
	}
}
