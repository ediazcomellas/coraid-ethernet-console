/* Copyright Coraid, Inc. 2013.  All Rights Reserved. */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "cec.h"

extern int fd;
static char hba_bytes[1<<14];
static int hba_len;

int
hbaopen(char *eth)
{
	if (strcmp(hbacecfile, "NOTSUPPORTED") == 0) {
		fprintf(stderr, "hba cec not supported\n");
		return -1;
	}
	fd = open(hbacecfile, O_RDWR);
	if (fd == -1) {
		perror("couldn't open hba cec file");
		return -1;
	}
	return 0;
}

int
hbarecv(void)
{
	hba_len = read(fd, hba_bytes, sizeof hba_bytes);
	if (debug) {
		printf("read %d bytes\r\n", hba_len);
		dump(hba_bytes, hba_len);
	}
	return hba_len;
}

int
hbaget(void *ap, int len)
{
	if (hba_len <= 0)
		return 0;
	if (len > hba_len)
		len = hba_len;
	memcpy(ap, hba_bytes, len);
	hba_len = 0;
	return len;
}

int
hbasend(void *p, int len)
{
	if (debug) {
		printf("sending %d bytes\r\n", len);
		dump(p, len);
	}
	if (len < 60)
		len = 60;
	return write(fd, p, len);
}

