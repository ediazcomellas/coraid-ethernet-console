/* Copyright Coraid, Inc. 2013. All rights reserved. */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include "pcap.h"
#include "cec.h"
#include <windows.h>
#include <winioctl.h>
#include "ntddndis.h" 

#define DEVICE_PREFIX   "\\\\.\\"

char hbacecfile[] = "NOTSUPPORTED";
int fd;
int pipefd[2];
char net_bytes[1<<14];
int net_off;
int net_len;
char srcaddr[6];
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
pthread_t pcaploop;

struct pkt_hdr {
	int size; 
};

struct pkt {
	struct pkt_hdr hdr;
	uchar data[1500];
};

DWORD
ndisquerystats(LPCTSTR adaptername, ULONG OidCode, PVOID buf, UINT buflen,
		PDWORD written)
{
	UCHAR fname[512];
	DWORD result = ERROR_SUCCESS;
	HANDLE mac;

	*written = 0;
	strcpy(fname, DEVICE_PREFIX);
	strcat(fname, adaptername);
	mac = CreateFile(fname, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
			0, INVALID_HANDLE_VALUE);
	if (mac != INVALID_HANDLE_VALUE) { 
		if(!DeviceIoControl(mac, IOCTL_NDIS_QUERY_GLOBAL_STATS, 
					&OidCode, sizeof OidCode , buf, buflen, 
					written, NULL)) 
			result = GetLastError();
	} else 
		result = GetLastError();
	return result;
}

char *
getmac(char *name)
{
	struct ifreq *ifr, *ifend;
	struct ifreq ifreq;
	struct ifconf ifc;
	struct ifreq ifs[64];
	int SockFD, len;

	len = sizeof ifreq.ifr_name / sizeof ifreq.ifr_name[0];
	ifreq.ifr_name[len - 1] = '\0';
	SockFD = socket(AF_INET, SOCK_DGRAM, 0);
	ifc.ifc_len = sizeof ifs;
	ifc.ifc_req = ifs;
	if (ioctl(SockFD, SIOCGIFCONF, &ifc) < 0)
		fprintf(stderr, "ioctl(SIOCGIFCONF): %m\n");
	ifend = ifs + (ifc.ifc_len / sizeof ifs[0]);
	for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
		strncpy(ifreq.ifr_name, ifr->ifr_name, len - 1);
		if (ioctl(SockFD, SIOCGIFHWADDR, &ifreq) < 0) {
			fprintf(stderr, "SIOCGIFHWADDR(%s): %m\n", 
				ifreq.ifr_name);
		}
		if (strcmp(name, ifreq.ifr_name) == 0) {
			memmove(srcaddr, ifreq.ifr_hwaddr.sa_data, 6);
			ifend = NULL;
		}
	}
	return srcaddr;
}

char *
getpcapname(char *mac)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char *ifname, *sptr;
	UCHAR OidData[4096];
	DWORD result, count = 0;

	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return NULL;
	}
	d = alldevs;
	for ( ; d; d = d->next) {
		sptr = strstr(d->name, "NPF_");
		if (sptr == NULL) {
			fprintf(stderr, "Error getting GUID\n");
			return NULL;
		}
	        result = ndisquerystats(sptr+4, OID_802_3_CURRENT_ADDRESS, 
					OidData, sizeof OidData, &count);
        	if(result != ERROR_SUCCESS) {
			continue;
		}
		if (count != 6)	{
			continue;
		}
		if (memcmp(mac, OidData, 6) == 0)	{
			ifname = malloc(strlen(d->name) + 1);
			if (ifname == NULL) {
				fprintf(stderr, "Malloc error for ifname\n");
				return NULL;
			}
			strcpy(ifname, d->name);	
			pcap_freealldevs(alldevs);		
			return ifname;
		}
	} 
	fprintf(stderr, "Adapter not found\n");
	return NULL;
}

void
pcap2pipe(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt_data)
{
	if (debug)
		fprintf(stderr, "%d bytes from wire\n", h->len);
	struct pkt tmp;
	tmp.hdr.size = h->len;
	memcpy(&tmp.data, pkt_data, h->len);
	write(pipefd[1], &tmp, sizeof tmp.hdr + h->len);
}

void *
pcaploop_thrd(void *ptr)
{
	pcap_loop(adhandle, 0, pcap2pipe, NULL);
	pcap_close(adhandle);
	return NULL;
}

int
netopen(char *eth)
{
	char *ifname;
	struct bpf_program fcode;
	bpf_u_int32 NetMask = 0xffffff;
	char filter[100];

	ifname = getpcapname(getmac(eth));
	if (ifname == NULL) {
		fprintf(stderr, "Error getting interface\n");
		return -1;
	}
	sprintf(filter, 
		"ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether proto 0xbcbc",
		(int)((unsigned char *)&srcaddr)[0],
		(int)((unsigned char *)&srcaddr)[1],
		(int)((unsigned char *)&srcaddr)[2],
		(int)((unsigned char *)&srcaddr)[3],
		(int)((unsigned char *)&srcaddr)[4],
		(int)((unsigned char *)&srcaddr)[5]);
	if ((adhandle = pcap_open_live(ifname, 65536, 0, 25, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open the adapter. %s is not "
			"supported by WinPcap\n", ifname);
		return -1;
	}
	if (pipe(pipefd) == -1) {
		fprintf(stderr, "Unable to create pipe\n");
		return -1;
	}
	if (pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0) {
		fprintf(stderr, "Error compiling pcap filter: wrong syntax.\n");
		pcap_close(adhandle);
		return -1;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "Error setting the pcap filter\n");
		pcap_close(adhandle);
		return -1;
	}
	fd = pipefd[0];
	pthread_create(&pcaploop, NULL, pcaploop_thrd, NULL);
	return fd;
}

int
netrecv(void)
{
	net_len = read(fd, net_bytes, sizeof net_bytes);
	net_off = 0;
	if (debug) {
		printf("read %d bytes\r\n", net_len);
		dump(net_bytes, net_len);
	}
	return net_len;
}

int
netget(void *ap, int len)
{
	int n, m;
	struct pkt_hdr *hdr;
	char *p;
	
	if (net_len <= 0)
		return 0;
	hdr = (struct pkt_hdr *)&net_bytes[net_off];
	p = net_bytes + net_off + sizeof hdr;
	n = hdr->size;
	if (n > len)
		n = len;
	memcpy(ap, p, n);
	m = hdr->size + sizeof hdr;
	net_off += m;
	net_len -= m;
	return n;
}

int
netsend(void *p, int len)
{
	int sendlen;
	memcpy(p+6, srcaddr, 6);
	if (debug) {
		printf("sending %d bytes\r\n", len);
		dump(p, len);
	}
	if (len < 60)
		len = 60;
	sendlen =  pcap_sendpacket(adhandle, p, len);
	if (sendlen == -1)
		fprintf(stderr, "error sending packet");
	else
		sendlen = len;
	return sendlen;
}

