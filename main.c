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

#include "tpool.h"

#define	DEFPORT	3000

int tcp;
unsigned short port = DEFPORT;
struct sockaddr_in sa;
unsigned char buf[BUFSIZ];
char namebuf[256];

char *CAcertfile;
char *certfile;
char *keyfile;
SSL_CTX *myctx;

typedef struct client {
	SSL *c_ssl;
	struct in_addr c_addr;
	int c_fd;
} client;

char *myname;
struct in_addr myaddr;

static void usage(char *prog)
{
	fprintf(stderr,
		"usage: %s [-a address] [-h hostFQDN] [-p port] [-C CAcertfile] [-c certfile] [-k keyfile]\n", prog);
	exit(EXIT_FAILURE);
}

void *do_client(void *arg);

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
	 */

	while ((i = getopt(argc, argv, "a:c:h:k:p:C:")) != EOF) {
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
		default:
			usage(prog);
		}
	}

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

	if ((tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		sock_err("tcp socket");
		exit(1);
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = myaddr.s_addr;

	if (bind(tcp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		sock_err("tcp bind");
		exit(1);
	}
	listen( tcp, 1 );
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
		}
		tpool_submit(do_client, cp);
	}
}
