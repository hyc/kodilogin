/* Copyright (C) 2026 by Howard Chu.
 * http://www.highlandsun.com/hyc/
 *
 * You may distribute this program under the terms of the
 * GNU General Public License version 2.
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

typedef struct client {
	SSL *c_ssl;
	struct in_addr c_addr;
	char c_addrstr[INET_ADDRSTRLEN+1];
	int c_addrstrlen;
	int c_fd;
} client;

#define CODE_OK	"200 OK"
#define CODE_ACCEPTED "202 Accepted"
#define CODE_FOUND "302 Found"
#define CODE_UNAUTHORIZED "401 Unauthorized"
#define CODE_NOT_FOUND "404 Not Found"

char *myname;
struct in_addr myaddr;
myval callbackUrl;
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

	i = ((CAcertfile != NULL) << 2) | ((certfile != NULL) << 1) | (keyfile != NULL);
	if (i) {
		if (i != 7) {
			fprintf(stderr, "Invalid or incomplete TLS options\n");
			exit(1);
		}
		OPENSSL_init_ssl(0, NULL);
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

	i = sizeof("http://:xxxxx/callback") + strlen(myname);
	if (myctx) i++;
	callbackUrl.mv_val = malloc(i+1);
	if (!callbackUrl.mv_val) {
		perror("malloc");
		exit(1);
	}
	callbackUrl.mv_len = sprintf(callbackUrl.mv_val, "http%s://%s:%d/callback", myctx ? "s" : "", myname, port);

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
	ptr += sprintf(ptr, "Content-Length: %d\r\n", len);
	if (headers)
		ptr = strcopy(ptr, headers->mv_val);
	*ptr++ = '\r'; *ptr++ = '\n';
	memcpy(ptr, text->mv_val, text->mv_len);
	ptr += len;
	len = ptr - pbuf;
	my_send(cp, pbuf, len);
	if (pbuf != buf)
		free(pbuf);
}

void do_authz(client *cp, cacherec *cr);

void *do_client(void *arg) {
	client *cp = arg;
	unsigned char ibuf[32768], *ptr;
	int num;
	myval resp;

	if (cp->c_ssl) {
		if (!SSL_accept(cp->c_ssl)) {
			fprintf(stderr, "SSL_accept failed\n");
			return NULL;
		}
	}

	inet_ntop(AF_INET, &cp->c_addr, cp->c_addrstr, INET_ADDRSTRLEN);
	cp->c_addrstrlen = strlen(cp->c_addrstr);

	for(;;) {
		num = my_recv(cp, ibuf, sizeof(ibuf));
		if (num <= 0)
			break;
		ibuf[num] = '\0';
		switch(ibuf[0]) {
		case 'G':
			if (!strncmp(ibuf+1, "ET /ip ", sizeof("ET /ip ")-1)) {
				resp.mv_val = cp->c_addrstr;
				resp.mv_len = cp->c_addrstrlen;
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
						ptr = strstr(pinv.mv_val + PINLEN, "Authorization");
						if (ptr && cr->c_owner.mv_len == cp->c_addrstrlen &&
							!strncmp(cr->c_owner.mv_val, cp->c_addrstr, cp->c_addrstrlen)) {
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
												if (!cr->c_tokeninfo) {
													resp.mv_val = "";
													resp.mv_len = 0;
													do_resp(cp, CODE_ACCEPTED, "text/json", NULL, &resp);
												} else {
													do_resp(cp, CODE_OK, "text/json", NULL, &cr->c_tokeninfo->t_text);
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
"</form></body></html>\n"
				resp.mv_val = MAINPAGE;
				resp.mv_len = sizeof(MAINPAGE)-1;
				do_resp(cp, CODE_OK, "text/html", NULL, &resp);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /authorize?", sizeof("ET /authorize"))) {
				ptr = ibuf+sizeof("ET /authorize");
				if (ptr[PINLEN] == ' ') {
					cacherec *cr;
					myval pinv;
					pinv.mv_val = ptr;
					pinv.mv_len = PINLEN;
					cr = cacheGet(&pinv);
					if (cr && cr->c_owner.mv_len == cp->c_addrstrlen &&
						!strncmp(cp->c_addrstr, cr->c_owner.mv_val, cr->c_owner.mv_len)) {
						do_authz(cp, cr);
						my_clos(cp);
						break;
					}
				}
				resp.mv_val = "Invalid PIN";
				resp.mv_len = sizeof("Invalid PIN")-1;
				do_resp(cp, CODE_UNAUTHORIZED, "text/plain", NULL, &resp);
				my_clos(cp);
			}
			break;
		case 'P':
			if (!strncmp(ibuf+1, "OST /pin ", sizeof("OST /pin ")-1)) {
				/* generate new pin */
				unsigned char pinbuf[PINLEN+1], passbuf[129];
				myval pinv = {pinbuf, sizeof(pinbuf)-1};
				myval passv = {passbuf, sizeof(passbuf)-1};
				myval prov;
				myval owner = {cp->c_addrstr, cp->c_addrstrlen};
				cacherec *cr;
				int len;

				prov.mv_val = strstr(ibuf, "provider=");
				if (!prov.mv_val)
					break;
				prov.mv_val += sizeof("provider");
				prov.mv_len = strlen(prov.mv_val);
				generatePin(&pinv);
				generatePassword(&passv);
				cr = cacheSet(&pinv, &passv, &prov, &owner);
				if (cr)
					do_resp(cp, CODE_OK, "text/json", NULL, &cr->c_text);
				my_clos(cp);
			}
			break;
		}
	}

	return NULL;
}

#define AUTHZ_URL "https://accounts.google.com/o/oauth2/v2/auth?"
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
		sizeof(ACCESS_TYPE) + sizeof(PROMPT) + PINLEN;
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
		header.mv_len = ptr - header.mv_val;
		resp.mv_val = "";
		resp.mv_len = 0;
		do_resp(cp, CODE_FOUND, "text/plain", &header, &resp);
		free(header.mv_val);
	}
}
