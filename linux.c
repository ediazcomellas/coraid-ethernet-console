/* Copyright Coraid, Inc. 2013.  All rights reserved. */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/fs.h>
#include <sys/stat.h>

#include "cec.h"

int fd;
char net_bytes[1<<14];
int net_len;
char srcaddr[6];
char hbacecfile[] = "/proc/ethdrv/cec";

int
getindx(int s, char *name)	// return the index of device 'name'
{
	struct ifreq xx;
	int n;

	strcpy(xx.ifr_name, name);
	n = ioctl(s, SIOCGIFINDEX, &xx);
	if (n == -1)
		return -1;
	return xx.ifr_ifindex;
}

int
netopen(char *eth)		// get us a raw connection to an interface
{
	int i, n;
	struct sockaddr_ll sa;
	struct ifreq xx;

	memset(&sa, 0, sizeof sa);
	fd = socket(PF_PACKET, SOCK_RAW, htons(CEC_ETYPE));
	if (fd == -1) {
		perror("got bad socket");
		return -1;
	}
	i = getindx(fd, eth);
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(CEC_ETYPE);
	sa.sll_ifindex = i;
	n = bind(fd, (struct sockaddr *)&sa, sizeof sa);
	if (n == -1) {
		perror("bind funky");
		return -1;
	}
        strcpy(xx.ifr_name, eth);
	n = ioctl(fd, SIOCGIFHWADDR, &xx);
	if (n == -1) {
		perror("Can't get hw addr");
		return -1;
	}
	memmove(srcaddr, xx.ifr_hwaddr.sa_data, 6);
	return 0;
}

int
netrecv(void)
{
	net_len = read(fd, net_bytes, sizeof net_bytes);
	if (debug) {
		printf("read %d bytes\r\n", net_len);
		dump(net_bytes, net_len);
	}
	return net_len;
}

int
netget(void *ap, int len)
{
	if (net_len <= 0)
		return 0;
	if (len > net_len)
		len = net_len;
	memcpy(ap, net_bytes, len);
	net_len = 0;
	return len;
}

int
netsend(void *p, int len)
{
	memcpy(p+6, srcaddr, 6);
	if (debug) {
		printf("sending %d bytes\r\n", len);
		dump(p, len);
	}
	if (len < 60)
		len = 60;
	return write(fd, p, len);
}

