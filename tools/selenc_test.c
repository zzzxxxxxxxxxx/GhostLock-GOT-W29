/* Verify the select() res_out/res_ex encoding used by the GOT_SELECT_CARRIER:
 * res_out[i] = out[i] & (POLLOUT-ready fds), res_ex[i] = ex[i] &
 * (POLLPRI-ready fds).  out-set fds -> pipe write end (always POLLOUT);
 * ex-set fds -> TCP socket with pending OOB (MSG_OOB -> POLLPRI). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

static uint64_t fdset_word(const fd_set *set, int word)
{
	uint64_t v;
	memcpy(&v, (const char *)set + word * 8, 8);
	return v;
}

int main(void)
{
	/* ensure the loopback is up (QEMU virt has no NIC; lo exists but may
	 * be down, and the OOB socket needs a route to 127.0.0.1) */
	{
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s >= 0) {
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
			if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
				ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
				(void)ioctl(s, SIOCSIFFLAGS, &ifr);
			}
			close(s);
		}
	}

	fd_set in, out, ex;
	FD_ZERO(&in);
	FD_ZERO(&out);
	FD_ZERO(&ex);
	for (int fd = 128; fd < 192; fd++)
		FD_SET(fd, &out);       /* res_out words 2-3-4 */
	for (int fd = 192; fd < 320; fd++)
		FD_SET(fd, &ex);        /* res_ex words 3-4 */

	int p[2];
	if (pipe(p) != 0) {
		printf("pipe failed\n");
		return 1;
	}
	printf("pipe ok\n");

	int l = socket(AF_INET, SOCK_STREAM, 0);
	printf("socket l=%d\n", l);
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(0x7f000001);
	if (bind(l, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    getsockname(l, (struct sockaddr *)&sa, &sl) != 0 ||
	    listen(l, 1) != 0) {
		printf("bind/listen failed\n");
		return 2;
	}
	printf("listen ok\n");
	int c = socket(AF_INET, SOCK_STREAM, 0);
	printf("socket c=%d\n", c);
	if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		printf("connect failed\n");
		return 3;
	}
	printf("connect ok\n");
	int peer = accept(l, NULL, NULL);
	if (peer < 0) {
		printf("accept failed\n");
		return 4;
	}
	printf("accept ok peer=%d\n", peer);
	(void)send(c, "x", 1, MSG_OOB);
	printf("oob sent\n");

	for (int fd = 128; fd < 192; fd++)
		dup2(p[1], fd);
	for (int fd = 192; fd < 320; fd++)
		dup2(peer, fd);

	struct timeval tv = { 1, 0 };
	printf("calling select...\n");
	int r = select(320, &in, &out, &ex, &tv);
	printf("select returned %d\n", r);
	printf("select_ret=%d res_out2=%016llx res_out3=%016llx "
	       "res_out4=%016llx res_ex3=%016llx res_ex4=%016llx\n",
	       r,
	       (unsigned long long)fdset_word(&out, 2),
	       (unsigned long long)fdset_word(&out, 3),
	       (unsigned long long)fdset_word(&out, 4),
	       (unsigned long long)fdset_word(&ex, 3),
	       (unsigned long long)fdset_word(&ex, 4));
	return 0;
}
