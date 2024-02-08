/* cec.h: definitions for cec */

typedef unsigned char uchar;

#ifdef __APPLE__
typedef unsigned int uint;
#endif

int debug;
char *progname;
extern char hbacecfile[];

int netopen(char *name);
int netsend(void *, int);
int netrecv(void);
int netget(void *, int);

void rawon(void);
void rawoff(void);
void dump(char *, int);
void exits(char *);

enum { FQUOTE = (1<<0), FEMPTY = (1<<1) };
int getfields(char *, char **, int, char *, int);
char *htoa(char *, char *, uint);
int parseether(char *, char *);

#define tokenize(A, B, C) getfields((A), (B), (C), " \t\r\n", FQUOTE)

enum {
	CEC_ETYPE = 0xBCBC,
};

#define VERSION "cec-14"

