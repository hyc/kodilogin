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
	int c_fd;
} client;

#define CODE_OK	"200 OK"

char *myname;
struct in_addr myaddr;

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

	if ((tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		sock_err("tcp socket");
		exit(1);
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = myaddr.s_addr;

	tpool_init(my_max_thr);

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

void do_resp(client *cp, char *code, char *mtype, char *text)
{
	char buf[16384], *pbuf, *ptr;
	int len = strlen(text);
	if (len+100 > sizeof(buf)) {
		pbuf = malloc(len+100);
	} else {
		pbuf = buf;
	}
	ptr = pbuf;
	ptr += sprintf(ptr, "HTTP/1.1 %s\r\n", code);
	ptr += sprintf(ptr, "Content-Type: %s\r\n", mtype);
	ptr += sprintf(ptr, "Content-Length: %d\r\n\r\n", len);
	strcpy(ptr, text);
	ptr += len;
	len = ptr - pbuf;
	my_send(cp, pbuf, len);
	if (pbuf != buf)
		free(pbuf);
}

void *do_client(void *arg) {
	client *cp = arg;
	char ibuf[32768], *ptr;
	int num;

	if (cp->c_ssl) {
		if (!SSL_accept(cp->c_ssl)) {
			fprintf(stderr, "SSL_accept failed\n");
			return NULL;
		}
	}
	for(;;) {
		num = my_recv(cp, ibuf, sizeof(ibuf));
		if (num <= 0)
			break;
		switch(ibuf[0]) {
		case 'G':
			if (!strncmp(ibuf+1, "ET /ip ", sizeof("ET /ip ")-1)) {
				inet_ntop(AF_INET, &cp->c_addr, ibuf, INET_ADDRSTRLEN);
				do_resp(cp, CODE_OK, "text/plain", ibuf);
				my_clos(cp);
			} else if (!strncmp(ibuf+1, "ET /pin/", sizeof("ET /pin/")-1)) {
				/* lookup existing pin */
			}
			break;
		case 'P':
			if (!strncmp(ibuf+1, "OST /pin ", sizeof("OST /pin ")-1)) {
				/* get new pin */
			}
			break;
		}
	}

	return NULL;
}
