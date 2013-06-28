/*
 * Strobe (c) 1995-1997 Julian Assange (proff@suburbia.net),
 * All rights reserved.
 *
 * $ cc strobe.c -o strobe
 */

#define VERSION "1.05"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef _AIX
#  include <sys/select.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#if defined(solaris) || defined(linux) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__GCC__) || defined(__GNUC__)
#  define fvoid void
#else
#  define fvoid
extern int optind;
extern char *optarg;
#endif
#define bool int
#define FALSE 0
#define TRUE  1

#ifndef INADDR_NONE
#  define INADDR_NONE ((unsigned long)-1)
#endif

#define port_t (unsigned short)

/*
 * the below should be set via the Makefile, but if not...
 */

#ifndef ETC_SERVICES
#  define ETC_SERVICES "/etc/services"
#endif
#ifndef STROBE_SERVICES
#  define STROBE_SERVICES "strobe.services"
#endif
#ifndef LIB_STROBE_SERVICES
#  define LIB_STROBE_SERVICES "/usr/local/lib/strobe.services"
#endif

int a_timeout = 20;
int a_data_timeout = 30;
char *a_output = NULL;
char *a_services = "strobe.services";
char *a_input = NULL;
/* char *a_prescan = NULL; */
int a_start = 1;
int a_end = 65535;
int a_sock_max = 64;
int a_abort = 0;
int a_bindport = 0;
int a_capture = 1024;
int a_wrap = 79;
int a_lines = 1;
char *a_bindaddr = NULL;
char *a_dircap = NULL;
char *a_views = "all,hosts,networks,ports";
struct in_addr bindaddr;
bool f_linear = 0;
bool f_verbose = 0;
bool f_verbose_stats = 0;
bool f_fast = 0;
bool f_stats = 0;
bool f_quiet = 0;
bool f_delete_dupes = 0;
bool f_minimise = 0;
bool f_dontgetpeername = 0;
bool f_hexdump = 0;

int connects = 0;
int hosts_done = 0;
int attempts_done = 0;
int attempts_outstanding = 0;
struct timeval time_start;

fd_set set_sel_check_r;
fd_set set_sel_check_w;
fd_set set_sel_r;
fd_set set_sel_w;

int host_n;
int Argc;
char **Argv;

FILE *fh_input;

char *capture_buf;

#define HO_ACTIVE 1
#define HO_ABORT 2
#define HO_COMPLETING 4

struct hosts_s
{
    char *name;
    struct in_addr in_addr;
    int port;
    int *portlist;
    int portlist_n,portlist_alloc;
    int portlist_ent;
    struct timeval time_used;
    struct timeval time_start;
    int attempts;
    int attempts_done;
    int attempts_highest_done;
    int connects;
    time_t notice_abort;
    int status;
};
struct hosts_s ho_initial; /* the null template */
struct hosts_s *hosts;

#define HT_SOCKET 1
#define HT_CONNECTING 2
#define HT_CONNECTED 4

struct htuple_s
{
    char *name;
    struct in_addr in_addr;
    int port;
    int sfd;
    int status;
    struct timeval sock_start;
    int timeout;
    struct hosts_s *host;
    int data_lines;
    int data_len;
    u_char *data;
    int send_pos;
    int send_len;
    u_char *send;
};

struct htuple_s ht_initial;
struct htuple_s *attempt;

struct port_desc_s
{
    int port;
    char *name;
    char *portname;
    struct port_desc_s *next;
    struct port_desc_s *next_port;
};

struct port_desc_s **port_descs;

int *portlist = NULL;
int portlist_n = 0;

void display_port_sw (struct htuple_s *h);

char *
Srealloc (ptr, len)
  char *ptr;
  int len;
{
    char *p;
    int retries = 10;
    while (!(p = ptr? realloc (ptr, len): malloc(len)))
    {
        if (!--retries)
        {
		perror("malloc");
		exit(1);
	}
	if (!f_quiet)
	   fprintf(stderr, "Smalloc: couldn't allocate %d bytes...sleeping\n", len);
	sleep (2);
    }
    return p;
}

char *
Smalloc (len)
  int len;
{
   return Srealloc (NULL, len);
}

fvoid
sock_block (sfd)
  int sfd;
{
    int flags;
    flags = (~O_NONBLOCK) & fcntl (sfd, F_GETFL);
    fcntl (sfd, F_SETFL, flags);
}

fvoid
sock_unblock (sfd)
  int sfd;
{
    int flags;
    flags = O_NONBLOCK | fcntl (sfd, F_GETFL);
    fcntl (sfd, F_SETFL, flags);
}

int
timeval_subtract (result, x, y) /* why not floating point?  */
  struct timeval *result, *x, *y;
{
  result->tv_usec = x->tv_usec - y->tv_usec;
  result->tv_sec = x->tv_sec - y->tv_sec;
  if (result->tv_usec<0)
  {
    result->tv_usec+=1000000;
    result->tv_sec --;
  }
/* Return 1 if result is negative. */
return result->tv_sec < 0;
}

fvoid
attempt_clear (h)
  struct htuple_s *h;
{
    if (h->status & HT_CONNECTED)
        display_port_sw (h);
    if (h->status & HT_SOCKET)
    {
	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);
	timeval_subtract(&tv2, &tv1, &(h->sock_start));
	h->host->time_used.tv_sec+=tv2.tv_sec;
	if ((h->host->time_used.tv_usec+=tv2.tv_usec) >= 1000000)
	{
	    h->host->time_used.tv_usec -= 1000000;
	    h->host->time_used.tv_sec++;
	}
        attempts_done++;
	h->host->attempts_done++;
	if (h->port > h->host->attempts_highest_done)
	    h->host->attempts_highest_done=h->port;
	sock_unblock (h->sfd);
/*	shutdown (h->sfd, 2); */
	close (h->sfd);
        if ( (FD_ISSET(h->sfd, &set_sel_check_r)) || (FD_ISSET(h->sfd, &set_sel_check_w)) )
	{
	     FD_CLR (h->sfd, &set_sel_check_r);
             FD_CLR (h->sfd, &set_sel_check_w);
	     attempts_outstanding--;
	}
    }
    if (h->data)
        free(h->data);
    *h = ht_initial;
}

fvoid
clear_all ()
{
    int n;
    for (n = 0; n < a_sock_max; n++)
	attempt_clear (&attempt[n]);
}

fvoid
attempt_init ()
{
    int n;
    for (n = 0; n < a_sock_max; n++)
	attempt[n] = ht_initial;
}

fvoid
hosts_init ()
{
    int n;
    for (n = 0; n < a_sock_max; n++)
	hosts[n] = ho_initial;
}

fvoid
fdsets_init ()
{
    FD_ZERO(&set_sel_r); /* yes, we have to do this, despite the later */
    FD_ZERO(&set_sel_w); /* assisgnments */
    FD_ZERO(&set_sel_check_r);
    FD_ZERO(&set_sel_check_w);
}

int
sc_connect (h)
  struct htuple_s *h;
{
    struct sockaddr_in sa_in;
    int sopts1 = 1;
    struct linger slinger;
    if ((h->sfd = socket (PF_INET, SOCK_STREAM, 0)) == -1)
	return 0;
    memset(&sa_in, 0, sizeof(sa_in));
    h->status |= HT_SOCKET;
    gettimeofday(&(h->sock_start), NULL);
    sock_unblock (h->sfd);
    setsockopt (h->sfd, SOL_SOCKET, SO_REUSEADDR, (char *) &sopts1, sizeof (sopts1));
    setsockopt (h->sfd, SOL_SOCKET, SO_OOBINLINE, (char *) &sopts1, sizeof (sopts1));
    slinger.l_onoff = 0;	/* off */
    setsockopt (h->sfd, SOL_SOCKET, SO_LINGER, (char *) &slinger, sizeof (slinger));
    sa_in.sin_family = AF_INET;
    if (a_bindport)
        sa_in.sin_port = a_bindport;
    if (a_bindaddr)
        sa_in.sin_addr = bindaddr;
    if (a_bindaddr || a_bindport)
        if (bind (h->sfd, (struct sockaddr *)&sa_in, sizeof(sa_in)) == -1)
        {
		fprintf(stderr, "couldn't bind %s : %d  ", a_bindaddr? a_bindaddr: "0.0.0.0", ntohs(a_bindport));
		perror("");
		if (errno == EACCES)
			exit(1);
		return 0;
	}
    sa_in.sin_addr = h->in_addr;
    sa_in.sin_port = htons (h->port);

    h->host->attempts++;
    if (connect (h->sfd, (struct sockaddr *) &sa_in, sizeof (sa_in)) == -1)
    {
	switch (errno)
	{
	case EINPROGRESS:
	case EWOULDBLOCK:
	    break;
	case ETIMEDOUT:
	case ECONNREFUSED:
	case EADDRNOTAVAIL:
	    if (f_verbose)
	    {
		fprintf(stderr, "%s:%d ", h->name, h->port);
		perror("");
	    }
	    attempt_clear (h);
	    return 0;
	default:
	    if (!f_quiet)
	    {
	    	fprintf(stderr, "%s:%d ", h->name, h->port);
	    	perror ("");
	    }
	    attempt_clear (h);
	    return 0;
	}
    }
    h->status |= HT_CONNECTING;
    sock_block (h->sfd);
    FD_SET(h->sfd, &set_sel_check_r);
    FD_SET(h->sfd, &set_sel_check_w);
    attempts_outstanding++;
    return 1;
}

void
gen_port_simple (h, buf)
  struct htuple_s *h;
  char *buf;
{
    sprintf (buf, "%.128s %5d", h->name, h->port);
}

int
display_port_simple (h, fh)
  struct htuple_s *h;
  FILE *fh;
{
    char buf[256];
    gen_port_simple(h, buf);
    fputs(buf, fh);
    return strlen(buf);
}

void
display_port (h, fh)
  struct htuple_s *h;
  FILE *fh;
{
    int ds_len;
    ds_len = display_port_simple(h, fh);
    if (f_minimise)
	fputc('\n', fh);
    else
    {
        struct port_desc_s *pd;
    	if ((pd = port_descs[h->port]))
        {
    	    fprintf (fh, " %-12s %s\n", pd->portname, pd->name);
	    while (!f_delete_dupes && (pd=pd->next))
	        fprintf (fh, "%*s %-12s %s\n", ds_len, "", pd->portname, pd->name);
    	}
    	else
    	    fprintf (fh, " %-12s %s\n", "unassigned", "unknown");
    }
}

u_char *
conv_char(c, c2)
u_char c;
u_char c2;
{
        static u_char b[8];
	bzero(b, sizeof b);
	if (c=='\\')
	{
		b[0] = c;
		b[1] = c;
	} else
	if (c>=32 && c<127)
	{
		b[0] = c;
	} else
	if (c == '\r')
	{
		b[0] = '\\';
		b[1] = 'r';
	} else
	if (c == '\n')
	{
		b[0] = '\\';
		b[1] = 'n';
	} else
	if (c == '\t')
	{
		b[0] = '\\';
		b[1] = 't';
	} else
	if (c == 8)
	{
		b[0] = '\\';
		b[1] = 'b';
	} else
	if (c<32 || c >= 127)
	{
		/* remove possible ambiguity \n or \nn then digit */
		if (c<100 && isdigit(c2))
			sprintf (b, "\\%03d", (int)c);
		else
			sprintf (b, "\\%d", (int)c);
	} else
	{
		fprintf (stderr, "internal error in print_char");
	}
	return b;
}

void
asciidump (h, fh)
  struct htuple_s *h;
  FILE *fh;
{
    int n;
    int col = 0;
    char buf[256];
    int buf_len;
    char *p=h->data;
    gen_port_simple(h, buf);
    buf_len = strlen(buf);
    for (n=0; n<h->data_len; n++) {
        if (col == 0)
	{
	    if (!a_dircap)
	    {
	        if (f_minimise)
		{
		    fputs(buf, fh);
		    col = buf_len;
	        }
		else
		{
		    fprintf(fh, "%*s->", buf_len+1, "");
		}
		fputc(' ', fh);
	    }
	}
    	fputs(conv_char(p[n], (n==h->data_len-1)? '\0': p[n+1]), fh);
	col++;
	if (a_wrap)
	{
	    if (col >= a_wrap)
	    {
	        fputc('\n', fh);
		col = 0;
	    }
	    else
	    {
		switch (p[n])
		{
		 case '\0':
		 case '\n':
		    fputc('\n', fh);
		    col = 0;
		}
            }
       }
    }
   if (col !=0)
       fputc('\n', fh);
}

void
hexdump(h, fh)
  struct htuple_s *h;
  FILE *fh;
{
	int n;
    char buf[256];
    int buf_len;
    gen_port_simple(h, buf);
    buf_len = strlen(buf);
	for (n = 0; n < h->data_len; n+=12)
	{
		int y;
	    if (!a_dircap)
	    {
		if (f_minimise)
		{
		    fputs(buf, fh);
		}
		else
		{
		    fprintf(fh, "%*s->", buf_len+1, "");
		}
		fputc(' ', fh);
	    }
		for (y=0; y<12; y++)
		{
			if (y+n< h->data_len)
				fprintf(fh, "%02X ", h->data[n+y]);
			else
				fputs("   ", fh);
			if (y%4==3 && y!=11)
				fputc(' ', fh);
		}
		fputs(": ", fh);
		for (y=0; y<12; y++)
		{
			if (y+n< h->data_len)
				fprintf(fh, "%c", isprint(h->data[n+y])? h->data[n+y]: '.');
			else
				fputc(' ', fh);
		}
		fputc('\n', fh);
	}
	fputc('\n', fh);
}

char *
trslash (s)
  char *s;
{
    char *p=s;
    for (;*s; s++)
        if (*s == '/')
	    *s = ',';
    return p;
}
	    
/*
 * recursively build directory hierarchy, starting at leaf
 */

bool
blddir (name)
  char *name;
{
	char *p;

	if ((p = strrchr (name, '/')) == NULL)
		return FALSE;
	*p = '\0';
	if (mkdir (name, (mode_t) 0775) == -1)
		if (!blddir (name))
		{
			*p = '/';
			return FALSE;
		}
	if (mkdir (name, (mode_t) 0775) == -1)
	{
		if (errno != EEXIST)
		{
			fprintf(stderr, "error building directory hierarchy %s", name);
			*p = '/';
			return FALSE;
		}
	}
	*p = '/';
	return TRUE;
}

bool
makeln (char *from, char *to)
{
    if (link(from, to) !=0)
    {
        blddir(to);
	if (link(from, to) !=0)
	{
	    perror(to);
	    return FALSE;
	}
    }
    return TRUE;
}

void
display_port_sw (h)
  struct htuple_s *h;
{
    char master[1024];
    FILE *fh = stdout;

    if (a_dircap)
    {
        char buf[2048];
	char in[64];
	char *p;
        struct port_desc_s *pd;
	sprintf(master, "%.512s/strobe.%d", a_dircap, (int)getpid());
	fh = fopen(master, "w");
	if (!fh)
	{
	    blddir(master);
	    fh = fopen(master, "w");
	    if (!fh)
	    {
	        perror(master);
		return;
	    }
	}
	strcpy(in, inet_ntoa(h->host->in_addr));
	for (p=in; *p; p++)
	    if (*p == '.')
	        *p = '/';
    	pd = port_descs[h->port];
	if (strstr(a_views, "networks"))
	{
	        if (f_minimise)
			sprintf(buf, "%.512s/networks/%s/%s-%.256s/%05d", a_dircap, in, inet_ntoa(h->host->in_addr),
			        h->host->name, h->port);
		else
			sprintf(buf, "%.512s/networks/%s/%s-%.256s/%05d-%.200s-%.200s", a_dircap, in, inet_ntoa(h->host->in_addr),
			        h->host->name, h->port, pd? port_descs[h->port]->portname: "unknown", pd? trslash(port_descs[h->port]->name): "");
		makeln(master, buf);
	}
	if (strstr(a_views, "hosts"))
	{
	        if (f_minimise)
			sprintf(buf, "%.512s/hosts/%s-%.256s/%05d", a_dircap, inet_ntoa(h->host->in_addr),
			        h->host->name, h->port);
		else
			sprintf(buf, "%.512s/hosts/%s-%.256s/%05d-%.200s-%.200s", a_dircap, inet_ntoa(h->host->in_addr),
			        h->host->name, h->port, pd? port_descs[h->port]->portname: "unknown", pd? trslash(port_descs[h->port]->name): "");
		makeln(master, buf);
	}
	if (strstr(a_views, "all"))
	{
	        if (f_minimise)
			sprintf(buf, "%.512s/all/%.64s-%.200s-%05d", a_dircap, inet_ntoa(h->host->in_addr),
				h->host->name, h->port);
		else
			sprintf(buf, "%.512s/all/%.64s-%.200s-%05d-%.200s-%.200s", a_dircap, inet_ntoa(h->host->in_addr),
				h->host->name, h->port, pd? port_descs[h->port]->portname: "unknown", pd? trslash(port_descs[h->port]->name): "");
		makeln(master, buf);
	}
	if (strstr(a_views, "ports"))
	{
	        if (f_minimise)
			sprintf(buf, "%.512s/ports/%05d/%s-%.200s", a_dircap, h->port, inet_ntoa(h->host->in_addr),
				h->host->name);
		else
			sprintf(buf, "%.512s/ports/%05d-%.200s-%.200s/%.64s-%.200s", a_dircap, h->port, 
				pd? port_descs[h->port]->portname: "unknown", pd? trslash(port_descs[h->port]->name): "",
				inet_ntoa(h->host->in_addr), h->host->name);
		makeln(master, buf);
	}
    }
    if (h->status&HT_CONNECTED)
    {
	    if (!f_minimise && !a_dircap)
		    display_port(h, fh);
	    if (h->data_len>0)
	    {
		    if (f_hexdump)
			hexdump(h, fh);
		    else
			asciidump(h, fh);
	    }
    } 
    if (a_dircap)
    {
        fclose(fh);
        unlink(master);
    }
    if (!(h->status&HT_CONNECTED))
        display_port(h,fh);
}

void
init_capture_tcp (h)
  struct htuple_s *h;
{
    h->status&=~HT_CONNECTING;
    h->status|=HT_CONNECTED;
    FD_CLR (h->sfd, &set_sel_check_w);
}

void
capture_tcp (h)
  struct htuple_s *h;
{
    int cc;
    bool f_drop = 0;
    cc = recv(h->sfd, capture_buf, a_capture, 0);
    if (cc == 0)
    {
    	attempt_clear (h);
	return;
    }
    if (cc < 0)
    {
    	switch (errno)
	{
	 case EAGAIN:
	 case EINTR:
	    break;
	 default:
	    attempt_clear (h);
	}
	return;
    }
    if (h->data_len+cc>a_capture)
    {
        cc = a_capture - h->data_len;
	f_drop = 1;
    }
    if (a_lines)
    {
        int n;
	for (n=0; n<cc; n++)
	    if (capture_buf[n] == '\n' ||
	        capture_buf[n] == '\0')
	        h->data_lines++;
    }
    h->data_len+=cc;
    if (h->data)
        h->data = Srealloc(h->data, h->data_len);
    else
        h->data = Smalloc(h->data_len);
    memcpy(h->data+h->data_len-cc, capture_buf, cc);
    if (f_drop || h->data_lines >= a_lines)
        attempt_clear (h);
}

int
gatherer_tcp (h)
  struct htuple_s *h;
{
    h->host->connects++;
    connects++;
    if (a_capture)
    	init_capture_tcp (h);
    else 
    {
        display_port_sw (h);
	attempt_clear (h);
    }
    return 1;
}

int
gather (timeout_secs)
  int timeout_secs;
{
    struct timeval timeout;
    struct htuple_s *h;
    int n;
    int last = -1;
    int selected;
    time_t tim;

    if (!attempts_outstanding) return 1;
    set_sel_r=set_sel_check_r;
    set_sel_w=set_sel_check_w;

    if (timeout_secs)
    {
        timeout.tv_sec = timeout_secs;
        timeout.tv_usec = 0;
    }
    else
    {
        timeout.tv_sec = 0;
        timeout.tv_usec = 250000; /* 1/4 of a second */
    }
    
    
    selected = select (FD_SETSIZE, &set_sel_r, &set_sel_w, 0, &timeout);
    if (selected<0)
	perror ("select");

    tim = time (NULL);
    for ( n = 0 ; n < a_sock_max; n++ )
    {
        h = &attempt[n];
        if (h->status & HT_CONNECTED)
        {
            if (!FD_ISSET(h->sfd,&set_sel_r))
            {
              if ( (tim - h->sock_start.tv_sec) >= h->timeout)
              {
                attempt_clear(h);
              }
              continue;
            }
        }
	if (selected>0 && h->status & (HT_CONNECTING|HT_CONNECTED))
	{
	    if (FD_ISSET (h->sfd, &set_sel_r) ||
                FD_ISSET (h->sfd, &set_sel_w))
	    {
		struct sockaddr_in in;
		int len = sizeof (in);
		selected--;

                    
                /* select() lies occasionaly
                 */
		if (!f_dontgetpeername) /* but solaris2.3 crashes occasionally ;-| */
		{
			if (getpeername (h->sfd, (struct sockaddr *) &in, &len) == 0)
			{
			    if ((h->status & HT_CONNECTED) && FD_ISSET (h->sfd, &set_sel_r))
                                capture_tcp (h);
			    else
		    	        gatherer_tcp (h);
		        }
			else
		    	    attempt_clear (h);
		}
		else
		{
		    if ((h->status & HT_CONNECTED) &&
			FD_ISSET (h->sfd, &set_sel_r))
			capture_tcp (h);
		    else
			gatherer_tcp (h);
		}
	    }
	    last = n;
	} else
	{
	    if ((h->status & HT_SOCKET) &&
	        ((h->sock_start.tv_sec + h->timeout) < tim))
	    {
	        attempt_clear (h);
		last = n;
	    }
	}
    }
    return last;
}

bool
add_attempt (add)
  struct htuple_s *add;
{
    struct htuple_s *h;
    static time_t oldtime;
    int ret;
    for (;;)
    {
 	int n;
        int last;
	for (n=0; n < a_sock_max; n++)
	{
	    h = &attempt[n];
	    if (!h->status)
		goto foundfree;
	}
	last = gather (a_timeout);
	oldtime = time(NULL);
	if (last != -1) {
	   h = &attempt[last];
	   goto foundfree;
	}
    }
    foundfree:
    *h = *add;
    ret = sc_connect (h);
    if (oldtime+1<time(NULL)) {
	if (oldtime > 0)
		gather (0);
	oldtime = time(NULL);
    }
    return ret;
}

int
scatter (host, timeout)
  struct hosts_s *host;
  int timeout;
{
    static struct htuple_s add;
    add = ht_initial;
    add.host = host;
    add.name = host->name;
    add.in_addr = host->in_addr;
    add.port = host->port;
    add.timeout = timeout;
    if (f_verbose)
	fprintf (stderr, "attempting port=%d host=%s\n", add.port, add.name);
    add_attempt (&add);
    return 1;
}

fvoid
wait_end (t)
  int t;
{
    time_t st;
    st = time (NULL);
    while ((st + t) > time (NULL))
    {
	gather (a_timeout);
	if (attempts_outstanding<1) break;
    }
}

struct in_addr
resolve (name)
  char *name;
{
    static struct in_addr in;
    unsigned long l;
    struct hostent *ent;
    if ((l = inet_addr (name)) != INADDR_NONE)
    {
	in.s_addr = l;
	return in;
    }
    if (!(ent = gethostbyname (name)))
    {
	perror (name);
	in.s_addr = INADDR_NONE;
	return in;
    }
    return *(struct in_addr *) ent->h_addr;
}

char *
next_host ()
{
    static char lbuf[512];
    if (a_input)
    {
	int n;
reread:
	if (!fgets (lbuf, sizeof (lbuf), fh_input))
	{
	    fclose (fh_input);
            a_input = NULL;
	    return next_host();
	}
	if (strchr("# \t\n\r", lbuf[0])) goto reread;
	n = strcspn (lbuf, " \t\n\r");
	if (n)
	    lbuf[n] = '\0';
        hosts_done++;
	return lbuf;
    }
    if ( host_n >= Argc )
      return NULL;

    hosts_done++;
    return Argv[host_n++];
}

int
next_port (h)
struct hosts_s *h;
{
    int n;
    if (f_fast)
        return (++h->portlist_ent>portlist_n)?-1:portlist[h->portlist_ent-1];
    else if (h->portlist)
    {
        return (++h->portlist_ent>h->portlist_n)?-1:h->portlist[h->portlist_ent-1];
    }
    else
    {
        for (n = h->port; ++n <= a_end;)
        {
            return n;
        }
    }
    return -1;
}

int
add_port(h,p)
  struct hosts_s *h;
  int p;
{
    if (!p)
        return 0;
    if (h->portlist_n == h->portlist_alloc)
    {
        h->portlist_alloc += 20;
        h->portlist=(int *)Srealloc(h->portlist,h->portlist_alloc*sizeof(int));
    }
    h->portlist[h->portlist_n++]=p;
    return p;
}

bool
host_init (h, name, nocheck)
  struct hosts_s *h;
  char *name;
  bool nocheck;
{
    int n;
    char *ports;
    
    *h=ho_initial;
    if ((ports=strchr(name,':')))
    {
        char *pstart, *minus;
        int i, stopnow=0;
        int lastport;
        
        *ports=0;
        pstart=++ports;
        while(!stopnow)
        {
            switch(*ports)
            {
                case '\0':
                    stopnow=1;
                    /* FALL THROUGH */
                case ',':
                case ':':
                    *ports=0;
                    if ((minus=strchr(pstart,'-')))
                    {
                        *minus=0;
                        lastport=atoi(minus++);

                        for(i=atoi(pstart);i<=lastport;i++)
                            if (!add_port(h,i))
                            {
                                stopnow=2;
                                break;
                            }
                    }
                    else
                    {
                        if (!add_port(h,atoi(pstart)))
                            stopnow=2;
                    }
                    pstart=ports+1;
                    break;
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                case '-':
                    break;
                default:
                    stopnow=2;
            }
            ports++;
        }
        if (stopnow==2)
        {
            fprintf(stderr,"Couldn't parse port specifier\n");
            exit(1);
        }
    }
    h->in_addr = resolve (name);
    if (h->in_addr.s_addr == INADDR_NONE)
	return 0;
    if (!nocheck)
        for (n=0; n<a_sock_max; n++)
   	{ 
	    if (hosts[n].name && hosts[n].in_addr.s_addr==h->in_addr.s_addr)
	    {
		if (!f_quiet)
		    fprintf(stderr, "ip duplication: %s == %s (last host ignored)\n",
		        hosts[n].name, name);
		return 0;
	    }
        }
    h->name = (char *) Smalloc (strlen (name) + 1);
    strcpy (h->name, name);
    if(f_fast || h->portlist)
        h->port=next_port(h);
    else
        h->port = a_start;
    h->status = HO_ACTIVE;
    gettimeofday(&(h->time_start), NULL);
    return 1;
}

fvoid
host_clear (h)
  struct hosts_s *h;
{
    if (h->name)
    {
    	free (h->name);
    }
    *h=ho_initial;
}

fvoid
host_stats (h)
  struct hosts_s *h;
{
    struct timeval tv, tv2;
    float t, st;
    gettimeofday(&tv, NULL);
    timeval_subtract(&tv2, &tv, &(h->time_start));
    t = tv2.tv_sec+(float)tv2.tv_usec/1000000.0;
    st = h->time_used.tv_sec+(float)h->time_used.tv_usec/1000000.0;
    fprintf(stderr, "stats: host = %s trys = %d cons = %d time = %.2fs trys/s = %.2f trys/ss = %.2f\n",
	h->name, h->attempts_done, h->connects, t, h->attempts_done/t, h->attempts_done/st);
}

fvoid
final_stats()
{
    struct timeval tv, tv2;
    float t;
    gettimeofday(&tv, NULL);
    timeval_subtract(&tv2, &tv, &(time_start));
    t = tv2.tv_sec+(float)tv2.tv_usec/1000000.0;
    fprintf(stderr, "stats: hosts = %d trys = %d cons = %d time = %.2fs trys/s = %.2f\n",
	hosts_done, attempts_done, connects, t, attempts_done/t);
}

bool skip_host(h)
  struct hosts_s *h;
{
    if (a_abort && !h->connects && (h->attempts_highest_done >= a_abort)) /* async pain */
    {
	if (h->status & HO_ABORT)
	{
	    if ((time(NULL)-h->notice_abort)>a_timeout)
	    {
		if (f_verbose)
		    fprintf(stderr, "skipping: %s (no connects in %d attempts)\n",
			h->name, h->attempts_done);
		return 1;
	    }
	} else 
        {
		h->notice_abort=time(NULL);
		h->status|=HO_ABORT;
	}
    }
    return 0;
}

fvoid
scan_ports_linear ()
{
    struct hosts_s host;
    char *name;
    while ((name = next_host ()))
    {
	if (!host_init(&host, name, 1)) continue;
	for (;;)
	{
	    scatter (&host, a_timeout);
	    if (skip_host(&host)) break;
	    if ((host.port = next_port(&host))==-1)
		break;
	}
	wait_end (a_timeout);
	if (f_verbose_stats)
	    host_stats (&host);
	clear_all ();
	host_clear(&host);
    }
}

/* Huristics:
 *  o  fast connections have priority == maximise bandwidth i.e 
 *     a port in the hand is worth two in the bush
 *
 *  o  newer hosts have priority == lower ports checked more quickly
 *
 *  o  all hosts eventually get equal "socket time" == despite
 *     priorities let no one host hog the sockets permanently
 *
 *  o  when host usage times are equal (typically on or shortly after
 *     initial startup) distribute hosts<->sockets evenly rather than
 *     play a game of chaotic bifurcatic ping-pong
 */
          
fvoid
scan_ports_paralell ()
{
    int n;
    struct timeval smallest_val;
    int smallest_cnt;
    char *name;
    struct hosts_s *h, *smallest;
    struct hosts_s *anyhost;
    do 
    {
	smallest_val.tv_sec=0xfffffff;
	smallest_val.tv_usec=0;
	for (n = 0, smallest_cnt = 0xfffffff, anyhost= smallest = NULL; n < a_sock_max; n++)
	{
	    h = &hosts[n];

	    if (((h->status & HO_COMPLETING) &&
                 (h->attempts_done == h->attempts)) ||
                skip_host(h))
	    {
		if (f_verbose_stats) host_stats (h);
		host_clear (h);
	    }

	    if (!h->name && ((name = next_host ())))
		if (!host_init (h, name, 0))
		{
		    host_clear (h);
		    continue;
		}

	    if (h->name)
	    {
                anyhost=h;
		if ((((h->time_used.tv_sec < smallest_val.tv_sec) ||
		     ((h->time_used.tv_sec == smallest_val.tv_sec) &&
		      (h->time_used.tv_usec <= smallest_val.tv_usec))) &&
		    (((h->time_used.tv_sec != smallest_val.tv_sec) &&
		      (h->time_used.tv_usec != smallest_val.tv_usec)) ||
		     (h->attempts < smallest_cnt)))&&
                     !(h->status&HO_COMPLETING))
	        {
	  	    smallest_cnt = h->attempts;
		    smallest_val = h->time_used;
		    smallest = h;
		 }
	    }
	}

	if (smallest)
	{
/* scatter adds connection or calls gather() until one is freed   */
		scatter (smallest, a_timeout);
		if ((smallest->port=next_port(smallest))==-1)
	            smallest->status|=HO_COMPLETING;
	}
        else
            gather(a_timeout);
    }
    while(anyhost);
}

fvoid
loaddescs ()
{
    FILE *fh;
    char lbuf[1024];
    char desc[256];
    char portname[17];
    unsigned int port;
    char *fn;
    char prot[4];
    prot[3]='\0';
    if (!(fh = fopen ((fn=a_services), "r")) &&
        !(fh = fopen ((fn=LIB_STROBE_SERVICES), "r")) &&
        !(fh = fopen ((fn=ETC_SERVICES), "r")))
    {
	perror (fn);
	exit (1);
    }
    port_descs=(struct port_desc_s **) Smalloc(sizeof(struct port_descs_s *) * 65536);
    memset(port_descs, 0, 65536);
    while (fgets (lbuf, sizeof (lbuf), fh))
    {
	char *p;
	struct port_desc_s *pd, *pdp;
	if (strchr("*# \t\n", lbuf[0])) continue;
	if (!(p = strchr (lbuf, '/'))) continue;
	*p = ' ';
	desc[0]='\0';
	if (sscanf (lbuf, "%16s %u %3s %255[^\r\n]", portname, &port, prot, desc) <3 || strcmp (prot, "tcp") || (port > 65535))
	    continue;
	pd = port_descs[port];
	if (!pd)
	{
	    portlist = (int *)Srealloc((char *)portlist, ++portlist_n*sizeof(int));
	    portlist[portlist_n-1]=port;
	}
	pdp = (struct port_desc_s *) Smalloc (sizeof (*pd) + strlen (desc) + 1 + strlen (portname) + 1);
	if (pd)
	{
	    for (; pd->next; pd = pd->next);
	    pd->next = pdp;
	    pd = pd->next;
	} else 
	{
	    pd = pdp;
	    port_descs[port] = pd;
	} 
	pd->next = NULL;
	pd->name = (char *) (pd) + sizeof (*pd);
	pd->portname = pd->name + strlen(desc)+1;
	strcpy (pd->name, desc);
	strcpy (pd->portname, portname);
    }
    fclose (fh);
}

fvoid
usage ()
{
    fprintf (stderr, "\
usage: %8s [options]\n\
\t\t[-v(erbose)]\n\
\t\t[-V(erbose_stats]\n\
\t\t[-m(inimise)]\n\
\t\t[-d(elete_dupes)]\n\
\t\t[-g(etpeername_disable)]\n\
\t\t[-s(tatistics)]\n\
\t\t[-q(uiet)]\n\
\t\t[-o output_file]\n\
\t\t[-b begin_port_n]\n\
\t\t[-e end_port_n]\n\
\t\t[-p single_port_n]\n\
\t\t[-P bind_port_n]\n\
\t\t[-A bind_addr_n]\n\
\t\t[-t timeout_n]\n\
\t\t[-n num_sockets_n]\n\
\t\t[-S services_file]\n\
\t\t[-i hosts_input_file]\n\
\t\t[-l(inear)]\n\
\t\t[-f(ast)]\n\
\t\t[-a abort_after_port_n]\n\
\t\t[-c capture_n]\n\
\t\t[-w wrap_col_n]\n\
\t\t[-x(heXdump)]\n\
\t\t[-L capture_lines_n]\n\
\t\t[-D capture_directory]\n\
\t\t[-T capture_timeout_n]\n\
\t\t[-M(ail_author)]\n\
\t\t[host1 [...host_n]]\n", Argv[0]);
    exit (1);
}
int
main (argc, argv)
  int argc;
  char **argv;
{
    int c;
    Argc = argc;
    Argv = argv;

    while ((c = getopt (argc, argv, "o:dvVmgb:e:p:P:a:A:t:n:S:i:lfsqMc:w:xL:D:T:")) != -1)
	switch (c)
	{
	case 'o':
	    a_output = optarg;
	    break;
	case 'd':
	    f_delete_dupes=1;
	    break;
	case 'v':
	    f_verbose = 1;
	    break;
	case 'V':
	    f_verbose_stats = 1;
	    break;
	case 'm':
	    f_minimise = 1;
	    break;
	case 'g':
	    f_dontgetpeername = 1;
	    break;
	case 'b':
	    a_start = atoi (optarg);
	    break;
	case 'e':
	    a_end = atoi (optarg);
	    break;
	case 'P':
	    a_bindport = htons (atoi (optarg));
	    break;
	case 'A':
	    a_bindaddr = optarg;
	    bindaddr = resolve (a_bindaddr);
	    if (bindaddr.s_addr == INADDR_NONE)
	    {
	    	perror(a_bindaddr);
		exit(1);
	    }
            break;
	case 'p':
	    a_start = a_end = atoi (optarg);
	    break;
	case 'a':
	    a_abort = atoi (optarg);
	    break;
	case 't':
	    a_timeout = atoi (optarg);
	    break;
	case 'n':
	    a_sock_max = atoi (optarg);
	    break;
	case 'S':
	    a_services = optarg;
	    break;
	case 'i':
	    a_input = optarg;
	    break;
	case 'l':
	    f_linear = 1;
	    break;
	case 'f':
	    f_fast = 1;
	    break;
	case 's':
	    f_stats = 1;
	    break;
        case 'q':
	    f_quiet = 1;
	    break;
	case 'M':
	    fprintf(stderr, "Enter mail to author below. End with ^D or .\n");
	    system("mail strobe@suburbia.net");
	    break;
	case 'c':
	    a_capture = atoi(optarg);
	    break;
	case 'w':
	    a_wrap = atoi(optarg);
	    break;
	case 'x':
	    f_hexdump = 1;
	    break;
	case 'L':
	    a_lines = atoi(optarg);
	    break;
        case 'D':
            a_dircap = optarg;
            break;
	case 'T':
	    a_data_timeout = atoi (optarg);
	    break;
	case '?':
	default:
	    fprintf (stderr, "unknown option %s\n", argv[optind-1]);
	    usage ();
	    /* NOT_REACHED */
	}
    host_n = optind;

    if (!f_quiet)
        fprintf (stderr, "strobe %s (c) 1995-1999 Julian Assange <proff@iq.org>.\n", VERSION);
    if (a_input)
    {
        if ( ! strcmp("-",a_input) ) { /* Use stdin as input file */
	    fh_input = stdin;
	  }
	else {
	  if (!(fh_input = fopen (a_input, "r")))
	    {
	      perror (a_input);
	      exit (1);
	    }
	}
    } else
    {
      switch ( argc - host_n ) { /* Number of hosts found on command line */
      case 0:
	fh_input = stdin;
	a_input = "stdin"; /* Needed in "next_host()" */
	break;
      case 1:
	f_linear = 1;
	break;
      }
    }

    if ((fh_input==stdin) && !f_quiet)
      fprintf (stderr, "Reading host names from stdin...\n");

    if (a_output)
    {
        int fd;
        if ((fd=open(a_output, O_WRONLY|O_CREAT|O_TRUNC, 0666))==-1)
	{
		perror(a_output);
		exit(1);
	}
	dup2(fd, 1);
    }
    if (a_capture)
	    capture_buf = Smalloc(a_capture);
    attempt = (struct htuple_s *) Smalloc (a_sock_max * sizeof (struct htuple_s));
    attempt_init();
    if (!f_linear)
    {
    	hosts = (struct hosts_s *) Smalloc (a_sock_max * sizeof (struct hosts_s));
    	hosts_init();
    }
    loaddescs ();
    fdsets_init();
    gettimeofday(&time_start, NULL);
    f_linear ? scan_ports_linear ():
 	       scan_ports_paralell ();
    if (f_stats || f_verbose_stats)
	final_stats();
    exit (0);
}
