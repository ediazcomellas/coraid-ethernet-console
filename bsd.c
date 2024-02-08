/* Copyright Coraid, Inc. 2013.  All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <assert.h>
#include "cec.h"

char	hbacecfile[] = "NOTSUPPORTED";
int 	fd;
static	int	blen;
static	char	*net_bytes;
static	int	net_len;
static	int	net_off;
static 	char 	*iob;	// io buffer
static 	struct bpf_program prog;
static 	struct bpf_insn code[] = {
	//  code, jt, jf, k
	{ 0x0028,  0,  0, 12 },		// ld	[12:H]
	{ 0x0015,  2,  0, CEC_ETYPE },	// jeq	0xBAD1, 1
	{ 0x0006,  0,  0, 0 },		// ret 	k
	{ 0x0080,  0,  0, 0 },		// ld	LEN
	{ 0x0016,  0,  0, 0 },		// ret 	A
};
		
static int
getbpf(void)
{
	char buf[30];
	int i, f;
	
	for (i = 0; i < 256; i++) {
		snprintf(buf, sizeof buf, "/dev/bpf%d", i);
		f = open(buf, O_RDWR, 0);
		if (f != -1) {
			if (debug)
				fprintf(stderr, "opened %s\r\n", buf);
			return f;
		}
	}
	return -1;
}

void
eioctl(int fd, unsigned int cmd, void *arg, char *msg)
{
	extern int errno;
	
	if (ioctl(fd, cmd, arg) < 0) {
		fprintf(stderr, "%s: ioctl %s failed: %s\r\n", progname,
			msg, strerror(errno));
			exits("ioctl");
	}
}

int
netopen(char *net)
{
	int r;
	struct ifreq ir;
	
	fd = getbpf();
	if (fd == -1)
		return -1;
	eioctl(fd, BIOCGBLEN, &blen, "BIOCGBLEN");
	net_bytes = malloc(blen);
	assert(net_bytes != NULL);
	iob = malloc(blen);
	strcpy(ir.ifr_name, net);
	eioctl(fd, BIOCSETIF, &ir, "BIOCSETIF");
	r = 1;
	eioctl(fd, BIOCIMMEDIATE, &r, "BIOCIMMEDIATE");	// turn on
	r = 0;
	eioctl(fd, BIOCSSEESENT, &r, "BIOCSSEESENT");	// turn off
	prog.bf_len = sizeof(code) / sizeof (code[0]);
	prog.bf_insns = code;
	eioctl(fd, BIOCSETF, &prog, "BIOCSETF");
	return 0;
}

int
netsend(void *p, int len)
{
	//int i;
	
	if (debug) {
		printf("sending %d bytes\r\n", len);
	//	for (i = 0; i < 32 && i < len; i++)
	//		printf("%02x ", ((char *)p)[i] & 0xff);
	//	printf("\r\n");
	}
	if (len < 60)
		len = 60;
	return write(fd, p, len);
}

int
netrecv(void)
{
	int n;
	
	n = read(fd, net_bytes, blen);
	if (debug)
		printf("read %d bytes\r\n", n);
	net_len = n;
	net_off = 0;
	return n;
}

int
netget(void *ap, int len)
{
	int n, m;
	struct bpf_hdr *bp;
	char *p;
	
	if (net_len <= 0)
		return 0;
	bp = (struct bpf_hdr *)&net_bytes[net_off];
	if (debug) {
		printf("caplen=%d;", bp->bh_caplen);
		printf("datalen=%d;", bp->bh_datalen);
		printf("hdrlen=%d;", bp->bh_hdrlen);
		fflush(stderr);
	}
	p = net_bytes + net_off + bp->bh_hdrlen;
	n = bp->bh_caplen;
	if (n > len)
		n = len;
	memcpy(ap, p, n);
	m = BPF_WORDALIGN(bp->bh_hdrlen + bp->bh_caplen);
	net_off += m;
	net_len -= m;
	return n;
}

