/* Copyright © Coraid, Inc. 2013.  All Rights Reserved. */

#include <sys/time.h>
#include <sys/bufmod.h>
#include <sys/dlpi.h>
#include <sys/stream.h>
#include <stropts.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "cec.h"

enum{
	Dbufsz	= 8*1024,
};
typedef union DL_primitives Dlp;
extern int errno;
char hbacecfile[] = "/dev/ethdrv/cec";

int	fd;
char	rbuf[1<<14];
int	rlen;
char 	cbuf[1<<14];
char	srcaddr[6];

int
strioctl(int cmd, void *s, int l)
{
	struct strioctl m;

	m.ic_cmd = cmd;
	m.ic_timout = -1;
	m.ic_len = l;
	m.ic_dp = s;
	if(ioctl(fd, I_STR, &m) < 0)
		return -1;
	return m.ic_len;
}

static int
dlreq(void *v, int l)
{
	struct strbuf m;

	m.maxlen = 0;
	m.len = l;
	m.buf = v;
	return putmsg(fd, &m, 0, 0);
}

static int
dlrec(void *v, int l)
{
	static char buf[Dbufsz];
	struct strbuf m;
	int flags;

	m.maxlen = Dbufsz;
	m.len = 0;
	m.buf = buf;
	flags = 0;
	if(getmsg(fd, &m, 0, &flags) < 0)
		return -1;
	switch(((Dlp*)m.buf)->dl_primitive){
	case DL_INFO_ACK:
	case DL_BIND_ACK:
	case DL_OK_ACK:
	case DL_PHYS_ADDR_ACK:
		break;
	default:
		return -1;
	}
	if(m.len < l)
		return -1;
	if(v)
		memcpy(v, buf, l);
	return m.len;
}

static int
dlattach(int ppa)
{
	dl_attach_req_t m;

	m.dl_primitive = DL_ATTACH_REQ;
	m.dl_ppa = ppa;
	if(dlreq(&m, sizeof m) < 0)
		return -1;
	return dlrec(0, DL_OK_ACK_SIZE);
}

static int
dlbind(t_uscalar_t sap)
{
	dl_bind_req_t m;

	memset(&m, 0, sizeof m);
	m.dl_primitive = DL_BIND_REQ;
	m.dl_sap = sap;
	m.dl_service_mode = DL_CLDLS;
	if(dlreq(&m, sizeof m) < 0)
		return -1;
	return dlrec(0, DL_BIND_ACK_SIZE);
}

static Dlp*
dlinfo(void *v)
{
	dl_info_req_t r;

	r.dl_primitive = DL_INFO_REQ;
	if(dlreq(&r, sizeof r) < 0)
		return 0;
	if(dlrec(v, DL_INFO_ACK_SIZE) == 0)
		return 0;
	return (Dlp*)v;
}

static int
dlgetaddr(void)
{
	dl_phys_addr_req_t r;
	union{
		dl_phys_addr_ack_t t;
		char buf[Dbufsz];
	}u;

	r.dl_primitive = DL_PHYS_ADDR_REQ;
	r.dl_addr_type = DL_CURR_PHYS_ADDR;
	// vicious hack ... 6+sizeof u.t
	if(dlreq(&r, sizeof r) < 0 || dlrec(&u, 6+sizeof u.t) < 0)
		return -1;
	if(u.t.dl_addr_length != 6)
		return -1;
	memcpy(srcaddr, u.buf+u.t.dl_addr_offset, 6);
	return 0;
}

static int
_promis(int t)
{
	dl_promiscon_req_t m;

	memset(&m, 0, sizeof m);
	m.dl_primitive = DL_PROMISCON_REQ;
	m.dl_level = t;
	if(dlreq(&m, sizeof m) < 0)
		return -1;
	return dlrec(0, DL_OK_ACK_SIZE);
}

static int
promis(void)
{
//	return _promis(DL_PROMISC_PHYS) | _promis(DL_PROMISC_MULTI)
//		| _promis(DL_PROMISC_SAP);
	return _promis(DL_PROMISC_SAP);
}

// replace with ioctl as per linux verison?
static int
getunit(char *s)
{
	char *p, *e;
	int i;

	e = s + strlen(s);
	for(p = e-1; p > s && isdigit((unsigned char) *p); p--)
		;
	if(!isdigit((unsigned char) *p))
		p++;
	i = atoi(p);
	*p = 0;
	return i;
}

int
netopen(char *eth)
{
	int ppa;
	dl_info_ack_t *d;
	char buf[Dbufsz];

	ppa = getunit(eth);
loop:	fd = open(eth, O_RDWR);
	if(fd == -1){
		if(eth[0] != '/'){ // permit user to specify device sans path
			snprintf(buf, Dbufsz, "/dev/%s", eth);
			eth = strdup(buf);
			goto loop;
		}
		perror(eth);
		return -1;
	}
	if(dlattach(ppa) < 0 || dlbind(0) < 0){
		perror("dlpi");
		return -1;
	}
	if(promis() < 0){
		perror("promiscuous mode");
		return -1;
	}
	d = (dl_info_ack_t*)dlinfo(buf);
	if(d == 0 || d->dl_mac_type != DL_ETHER)
		return -1;
	if(dlgetaddr() == -1)
		return -1;
	if(strioctl(DLIOCRAW, 0, 0) < 0)
		return -1;
	return 0;
}

int
netrecv(void)
{
	struct strbuf m, c;
	int flags, r;

	c.buf = cbuf;
	c.maxlen = sizeof cbuf;
	c.len = 0;
	m.buf = rbuf;
	m.maxlen = sizeof rbuf;
	m.len = 0;
	flags = 0;
	r = getmsg(fd, &c, &m, &flags);
	if(r >= 0)
		rlen = m.len;
	else
		rlen = -1;
	if(debug){
		printf("read %d bytes [%d, %d, c.len=%d, f=%d]\r\n", rlen, r, errno, c.len, flags);
		dump(rbuf, rlen);
	}
	return rlen;
}

int
netget(void *v, int l)
{
	if (rlen <= 0)
		return 0;
	if (l > rlen)
		l = rlen;
	memcpy(v, rbuf, l);
	rlen = 0;
	return l;
}

int
netsend(void *v, int len)
{
	memcpy((char*)v+6, srcaddr, 6);
	if(debug){
		printf("sending %d bytes\r\n", len);
		dump(v, len);
	}
	if(len < 60)
		len = 60;
	return write(fd, v, len);
}
