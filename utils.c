/* Copyright Coraid, Inc.  2006.  All Rights Reserved */

#include <termios.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "cec.h"

static struct  termios attr;
static int raw;

void
_cfmakeraw(struct termios *t)
{
	t->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	t->c_oflag &= ~OPOST;
	t->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	t->c_cflag &= ~(CSIZE|PARENB);
	t->c_cc[VMIN] = 1;
	t->c_cflag |= CS8;
}

void
rawon(void)
{
	struct termios nattr;
	
	if (tcgetattr(STDIN_FILENO, &attr) != 0) {
		fprintf(stderr, "Can't make raw\n");
		return;
	}
	nattr = attr;
	_cfmakeraw(&nattr);
	tcsetattr(0, TCSAFLUSH, &nattr);
	raw = 1;
}

void
rawoff(void)
{
	if(raw)
		tcsetattr(0,TCSAFLUSH, &attr);
	raw = 0;
}

void
dump(char *ap, int len)
{
	int i;
	unsigned char *p = (unsigned char *) ap;

	for (i = 0; i < len; i++)
		fprintf(stderr, "%2.2X%s", p[i], (i+1)%16 ? " " : "\r\n");
	fprintf(stderr, "\r\n");
}

char *
htoa(char *to, char *frm, uint len)
{
	char *cp = to;
	uchar ch;

	for(; len > 0; len--, frm++) {
		ch = *frm;
		*to++ = (ch>>4) + (ch>>4 > 9 ? '7' : '0');
		*to++ = (ch&0x0f) + ((ch&0x0f) > 9 ? '7' : '0');
	}
	return cp;
}

/* parseether from plan 9 */
int
parseether(char *to, char *from)
{
	char nip[4];
	char *p;
	int i;

	p = from;
	for(i = 0; i < 6; i++){
		if(*p == 0)
			return -1;
		nip[0] = *p++;
		if(*p == 0)
			return -1;
		nip[1] = *p++;
		nip[2] = 0;
		to[i] = strtoul(nip, 0, 16);
		if(*p == ':')
			p++;
	}
	return 0;
}

/* rc style quoting and/or empty fields */
int
getfields(char *p, char **argv, int max, char *delims, int flags)
{
	uint n;

	n=0;
loop:
	if(n >= max || *p == '\0')
		return n;
	if(strchr(delims, *p)) {
		if(flags & FEMPTY) {
			*p = '\0';
			argv[n++] = p;
		}
		p++;
		goto loop;
	}

	switch(*p) {
	case '\'':
		if(flags & FQUOTE) {
			argv[n++] = ++p;
unq:
			p = strchr(p, '\'');
			if(p == NULL)
				return n;
			if(p[1] == '\'') {
				strcpy(p, p+1); /* too inefficient? */
				p++;
				goto unq;
			}
			break;
		}
	default:
		argv[n++] = p;
		do {
			if(*++p == '\0')
				return n;
		} while(!strchr(delims, *p));
	}
	*p++ = '\0';
	goto loop;
}

