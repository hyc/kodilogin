/* Copyright (C) 2005 by Howard Chu.
 * http://www.highlandsun.com/hyc/
 *
 * You may distribute this program under the terms of the
 * GNU General Public License version 2.
 *
 * Forward a port from localhost to some other server.
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
#define	sock_err(msg)	perror(msg)
#endif
#include <string.h>

#define	DEFPORT	3000

int tcp;
unsigned short lport = DEFPORT;
unsigned short rport;

struct sockaddr_in sa, da;

int lfd, rfd;

static void usage(char *prog)
{
	fprintf(stderr,
		"usage: %s -h address [-l localport] [-p port]\n", prog);
	exit(1);
}

int main( int argc, char *argv[] )
{
	int i, j;
	int got_h = 0, got_p = 0;
	char *prog = argv[0];
	fd_set sfds;

	/* -h: remote address to connect to
	 * -l: local port to bind to
	 * -p: remote port to bind to
	 */
	while ((i = getopt(argc, argv, "h:l:p:")) != EOF) {
		switch(i) {
		case 'h':
			if (!inet_aton(optarg, &da.sin_addr)) {
				fprintf(stderr, "Invalid address %s\n", optarg);
				exit(1);
			}
			got_h++;
			break;
		case 'l':
			lport = atoi(optarg);
			break;
		case 'p':
			rport = atoi(optarg);
			got_p++;
			break;
		default:
			usage(prog);
		}
	}

	if (!got_h)
		usage(prog);

	if (!got_p)
		rport = lport;

	if ((tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		sock_err("tcp socket");
		exit(1);
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(lport);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(tcp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		sock_err("tcp bind");
		exit(1);
	}

	da.sin_family = AF_INET;
	da.sin_port = htons(rport);

	listen( tcp, 1 );

	FD_ZERO(&sfds);
	for(;;) {
		fd_set sfds;
		lfd = accept(tcp, NULL, NULL);
		if ((rfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
			sock_err("rfd socket");
			exit(1);
		}
		if (connect(rfd, (struct sockaddr *)&da, sizeof(da)) < 0) {
			sock_err("rfd connect");
			exit(1);
		}
		for(;;) {
			char buf[2048], *ptr, *end;
			int len;
			FD_SET(lfd, &sfds);
			FD_SET(rfd, &sfds);

			i = select(rfd+1, &sfds, NULL, NULL, NULL);
			if (i < 1)
				break;
			if (FD_ISSET(lfd, &sfds)) {
				len = recv(lfd, buf, sizeof(buf), 0);
				if (len < 1)
					break;
				ptr = buf;
				end = ptr+len;
				while (ptr < end) {
					len = send(rfd, ptr, end-ptr, 0);
					if (len <= 0)
						break;
					ptr += len;
				}
			}
			if (FD_ISSET(rfd, &sfds)) {
				len = recv(rfd, buf, sizeof(buf), 0);
				if (len < 1)
					break;
				ptr = buf;
				end = ptr+len;
				while (ptr < end) {
					len = send(lfd, ptr, end-ptr, 0);
					if (len <= 0)
						break;
					ptr += len;
				}
			}
		}
		close(lfd);
		close(rfd);
	}
}
