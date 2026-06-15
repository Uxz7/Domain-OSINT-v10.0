/*
 * ============================================================
 *  Copyright (c) 2026 RussianHarvey
 *  All rights reserved.
 *
 *  DOMAIN OSINT v10.0 - Defensive Security Edition
 *  Cross-Platform: Windows + Linux
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software to use, copy, modify, and
 *  distribute for AUTHORIZED security assessments only.
 *
 *  Unauthorized use against systems you do not own or have
 *  explicit written permission to test is strictly prohibited
 *  and may violate local, national, and international laws.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 *  KIND. THE AUTHOR IS NOT RESPONSIBLE FOR ANY MISUSE.
 * ============================================================
 *
 *  [WINDOWS BUILD - MinGW]
 *    gcc -O2 -o domain_osint.exe domain_osint.c -lws2_32 -ldnsapi
 *
 *  [LINUX BUILD]
 *    gcc -O2 -o domain_osint domain_osint.c -lresolv -lpthread
 *
 *  [USAGE]
 *    ./domain_osint                    interactive
 *    ./domain_osint -d example.com
 *    ./domain_osint -d example.com --no-ports
 *    ./domain_osint --batch list.txt
 * ============================================================
 */
 
#if defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__)
#  define OS_WINDOWS 1
#  define WIN32_LEAN_AND_MEAN
#  define _WINSOCKAPI_
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  define OS_LINUX 1
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#define DNS_TYPE_TXT DNS_TYPE_TEXT

#ifndef DNS_TYPE_CAA
#define DNS_TYPE_CAA 0x0101
#endif

#ifdef OS_WINDOWS
#include <stdint.h>

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = af;
    memcpy(&sa.sin_addr, src, sizeof(struct in_addr));
    DWORD len = size;
    if (WSAAddressToStringA((struct sockaddr*)&sa, sizeof(sa), NULL, dst, &len) == 0) {
        return dst;
    }
    return NULL;
}

int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_in sa;
    int len = sizeof(sa);
    if (WSAStringToAddressA((LPSTR)src, af, NULL, (struct sockaddr*)&sa, &len) == 0) {
        memcpy(dst, &sa.sin_addr, sizeof(struct in_addr));
        return 1;
    }
    return 0;
}
#endif
/* ============================================================
 * INCLUDES
 * ============================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <windows.h>
 
#ifdef OS_WINDOWS
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <windns.h>
#  include <direct.h>
   typedef int socklen_t;
#  define SOCK_T   SOCKET
#  define BADSOCK  INVALID_SOCKET
#  define CLOSESOCK(s) closesocket(s)
#  define MKDIR(p)     _mkdir(p)
#  define SLEEP_MS(ms) Sleep(ms)
#  pragma comment(lib,"ws2_32.lib")
#  pragma comment(lib,"dnsapi.lib")
   static char *strcasestr(const char *h, const char *n) {
       if (!n||!*n) return (char*)h;
       size_t nl=strlen(n);
       for(;*h;h++) if(_strnicmp(h,n,nl)==0) return (char*)h;
       return NULL;
   }
#  define strncasecmp _strnicmp
#  define strcasecmp  _stricmp
#else
#  define _GNU_SOURCE
#  include <unistd.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <pthread.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/select.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <arpa/nameser.h>
#  include <resolv.h>
#  define SOCK_T   int
#  define BADSOCK  (-1)
#  define CLOSESOCK(s) close(s)
#  define MKDIR(p)     mkdir(p,0755)
#  define SLEEP_MS(ms) usleep((ms)*1000)
#endif
 
#ifdef OS_WINDOWS
typedef HANDLE   thr_t;
typedef DWORD    thr_ret;
#  define THR_CALL  WINAPI
#  define thr_create(t,fn,a) (*(t)=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(fn),(a),0,NULL), *(t)?0:-1)
#  define thr_join(t)        WaitForSingleObject((t),INFINITE)
#  define thr_close(t)       CloseHandle(t)
#else
typedef pthread_t thr_t;
typedef void*     thr_ret;
#  define THR_CALL
#  define thr_create(t,fn,a) pthread_create((t),NULL,(fn),(a))
#  define thr_join(t)        pthread_join((t),NULL)
#  define thr_close(t)       ((void)0)
#endif
 

static void net_init(void) {
#ifdef OS_WINDOWS
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
#else
    res_init(); signal(SIGPIPE,SIG_IGN);
#endif
}
static void net_cleanup(void) {
#ifdef OS_WINDOWS
    WSACleanup();
#endif
}
 

static int g_color = 1;
#define C_RED    (g_color?"\033[91m":"")
#define C_GREEN  (g_color?"\033[92m":"")
#define C_YELLOW (g_color?"\033[93m":"")
#define C_CYAN   (g_color?"\033[96m":"")
#define C_BOLD   (g_color?"\033[1m":"")
#define C_DIM    (g_color?"\033[2m":"")
#define C_RESET  (g_color?"\033[0m":"")
 
#define MAX_DOM     256
#define BUF_XL      131072
#define BUF_L       16384
#define BUF_M       4096
#define T_HTTP_MS   10000
#define T_PORT_MS   1400
#define MAX_NS      8
 
static char g_ip[64]      = {0};
static char g_org[256]    = {0};
static char g_country[64] = {0};
 
static void section(const char *t) {
    printf("\n%s%s"
           "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
           "  ◈ %s\n"
           "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
           "%s", C_RED, C_BOLD, t, C_RESET);
}
#define LOK(f,...)   printf("  %s[+]%s " f "\n", C_GREEN,  C_RESET, ##__VA_ARGS__)
#define LWARN(f,...) printf("  %s[!]%s " f "\n", C_YELLOW, C_RESET, ##__VA_ARGS__)
#define LINFO(f,...) printf("  %s[*]%s " f "\n", C_CYAN,   C_RESET, ##__VA_ARGS__)
#define LERR(f,...)  printf("  %s[-]%s " f "\n", C_RED,    C_RESET, ##__VA_ARGS__)
#define LVULN(f,...) printf("  %s%s[VULN]%s %s" f "%s\n", C_RED, C_BOLD, C_RESET, C_RED, ##__VA_ARGS__, C_RESET)
 

static void s_lower(char *s){for(;*s;s++)*s=(char)tolower((unsigned char)*s);}
static void s_trim(char *s){
    int l=(int)strlen(s);
    while(l>0&&(s[l-1]=='\r'||s[l-1]=='\n'||s[l-1]==' '||s[l-1]=='\t'))s[--l]='\0';
    int i=0; while(s[i]==' '||s[i]=='\t') i++;
    if(i) memmove(s,s+i,strlen(s+i)+1);
}
static void clean_dom(const char *r, char *o, size_t sz){
    const char *p=r;
    if(!strncmp(p,"https://",8))p+=8; else if(!strncmp(p,"http://",7))p+=7;
    if(!strncmp(p,"www.",4))p+=4;
    strncpy(o,p,sz-1); o[sz-1]='\0';
    for(char*q=o;*q;q++) if(*q=='/'||*q=='?'||*q=='#'){*q='\0';break;}
    s_lower(o); s_trim(o);
}
static int valid_dom(const char *d){
    if(!d||!*d) return 0;
    int dots=0,len=(int)strlen(d);
    if(len<4||len>253) return 0;
    for(int i=0;i<len;i++){
        char c=d[i];
        if(c=='.'){dots++;continue;}
        if(!isalnum((unsigned char)c)&&c!='-'&&c!='_') return 0;
    }
    return dots>=1;
}
static double now_s(void){
#ifdef OS_WINDOWS
    LARGE_INTEGER f,c;
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart/(double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec+ts.tv_nsec/1e9;
#endif
}
static void json_get(const char *j,const char *k,char *o,size_t sz){
    o[0]='\0';
    char p[128]; snprintf(p,sizeof(p),"\"%s\"",k);
    const char *f=strstr(j,p); if(!f) return;
    f=strchr(f,':'); if(!f) return; f++;
    while(*f==' '||*f=='"') f++;
    const char *e=strpbrk(f,"\",\r\n}"); if(!e) return;
    size_t l=(size_t)(e-f); if(l>=sz)l=sz-1;
    memcpy(o,f,l); o[l]='\0';
}
 

static int nb_connect(SOCK_T s, struct sockaddr *addr,
                      socklen_t addrlen, int ms)
{
#ifdef OS_WINDOWS
    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    connect(s,addr,addrlen);
    fd_set w; FD_ZERO(&w); FD_SET(s,&w);
    struct timeval tv={ms/1000,(ms%1000)*1000};
    int r=select((int)s+1,NULL,&w,NULL,&tv);
    nb=0; ioctlsocket(s,FIONBIO,&nb);
    if(r<=0) return -1;
    int err=0; int el=sizeof(err);
    getsockopt(s,SOL_SOCKET,SO_ERROR,(char*)&err,&el);
    return err?-1:0;
#else
    int fl=fcntl(s,F_GETFL,0);
    fcntl(s,F_SETFL,fl|O_NONBLOCK);
    connect(s,addr,addrlen);
    fd_set w; FD_ZERO(&w); FD_SET(s,&w);
    struct timeval tv={ms/1000,(ms%1000)*1000};
    int r=select(s+1,NULL,&w,NULL,&tv);
    fcntl(s,F_SETFL,fl);
    if(r<=0) return -1;
    int err=0; socklen_t el=sizeof(err);
    getsockopt(s,SOL_SOCKET,SO_ERROR,&err,&el);
    return err?-1:0;
#endif
}
 
static void sock_timeout(SOCK_T s, int ms){
#ifdef OS_WINDOWS
    DWORD t=(DWORD)ms;
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&t,sizeof(t));
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&t,sizeof(t));
#else
    struct timeval tv={ms/1000,(ms%1000)*1000};
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
#endif
}
 
static int dns_a(const char *host, char *out, size_t sz){
    out[0]='\0';
    struct addrinfo h={0},*r=NULL;
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&r)!=0) return -1;
    struct sockaddr_in *s=(struct sockaddr_in*)r->ai_addr;
    inet_ntop(AF_INET,&s->sin_addr,out,(socklen_t)sz);
    freeaddrinfo(r); return 0;
}
 

static int http_get(const char *host, int port,
                    const char *path, char *out, size_t outsz)
{
    out[0]='\0';
    struct addrinfo h={0},*r=NULL;
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    char ps[8]; snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host,ps,&h,&r)!=0) return -1;
    SOCK_T s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==BADSOCK){freeaddrinfo(r);return -1;}
    sock_timeout(s,T_HTTP_MS);
    if(connect(s,r->ai_addr,(socklen_t)r->ai_addrlen)!=0){
        CLOSESOCK(s); freeaddrinfo(r); return -1;
    }
    freeaddrinfo(r);
    char req[1024];
    snprintf(req,sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\n"
        "User-Agent: Mozilla/5.0 (DomainOSINT/10.0 by RussianHarvey)\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n", path, host);
    send(s,req,(int)strlen(req),0);
    int tot=0,n;
    while(tot<(int)outsz-1&&(n=recv(s,out+tot,(int)(outsz-(size_t)tot-1),0))>0)tot+=n;
    out[tot]='\0'; CLOSESOCK(s); return tot;
}
 
static int whois_q(const char *srv, const char *q, char *out, size_t sz){
    out[0]='\0';
    struct addrinfo h={0},*r=NULL;
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(srv,"43",&h,&r)!=0) return -1;
    SOCK_T s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==BADSOCK){freeaddrinfo(r);return -1;}
    sock_timeout(s,T_HTTP_MS);
    if(connect(s,r->ai_addr,(socklen_t)r->ai_addrlen)!=0){CLOSESOCK(s);freeaddrinfo(r);return -1;}
    freeaddrinfo(r);
    char req[MAX_DOM+4]; snprintf(req,sizeof(req),"%s\r\n",q);
    send(s,req,(int)strlen(req),0);
    int tot=0,n;
    while(tot<(int)sz-1&&(n=recv(s,out+tot,(int)(sz-(size_t)tot-1),0))>0)tot+=n;
    out[tot]='\0'; CLOSESOCK(s); return tot;
}
 
static void dns_txt(const char *qname, char *buf, size_t bsz){
    buf[0]='\0';
#ifdef OS_WINDOWS
    PDNS_RECORD pr=NULL;
    if(DnsQuery_A(qname,DNS_TYPE_TEXT,DNS_QUERY_STANDARD,NULL,&pr,NULL)!=ERROR_SUCCESS) return;
    size_t off=0;
    for(PDNS_RECORD r=pr;r&&off<bsz-2;r=r->pNext){
        if(r->wType!=DNS_TYPE_TEXT) continue;
        for(DWORD i=0;i<r->Data.TXT.dwStringCount&&off<bsz-2;i++){
            const char *t=r->Data.TXT.pStringArray[i];
            size_t tl=strlen(t); if(tl>bsz-off-2)tl=bsz-off-2;
            memcpy(buf+off,t,tl); off+=tl;
        }
        if(off<bsz-1) buf[off++]='\n';
    }
    buf[off]='\0';
    DnsRecordListFree(pr,DnsFreeRecordList);
#else
    unsigned char ans[NS_MAXMSG];
    int len=res_query(qname,C_IN,ns_t_txt,ans,sizeof(ans));
    if(len<0) return;
    ns_msg msg; if(ns_initparse(ans,len,&msg)<0) return;
    int cnt=ns_msg_count(msg,ns_s_an);
    size_t boff=0;
    for(int i=0;i<cnt&&boff<bsz-2;i++){
        ns_rr rr; if(ns_parserr(&msg,ns_s_an,i,&rr)) continue;
        if(ns_rr_type(rr)!=ns_t_txt) continue;
        const unsigned char *rd=ns_rr_rdata(rr);
        int rdlen=(int)ns_rr_rdlen(rr),off=0;
        while(off<rdlen&&boff<bsz-2){
            int sl=rd[off++];
            int cp=sl<rdlen-off?sl:rdlen-off;
            if((int)(bsz-boff-1)<cp)cp=(int)(bsz-boff-1);
            memcpy(buf+boff,rd+off,(size_t)cp);
            boff+=(size_t)cp; off+=cp;
        }
        if(boff<bsz-1) buf[boff++]='\n';
    }
    buf[boff]='\0';
#endif
}
 
static int dns_ns(const char *dom, char out[][MAX_DOM], int max){
    int found=0;
#ifdef OS_WINDOWS
    PDNS_RECORD pr=NULL;
    if(DnsQuery_A(dom,DNS_TYPE_NS,DNS_QUERY_STANDARD,NULL,&pr,NULL)==ERROR_SUCCESS){
        for(PDNS_RECORD r=pr;r&&found<max;r=r->pNext){
            if(r->wType!=DNS_TYPE_NS) continue;
            strncpy(out[found++],r->Data.NS.pNameHost,MAX_DOM-1);
        }
        DnsRecordListFree(pr,DnsFreeRecordList);
    }
#else
    unsigned char ans[NS_MAXMSG];
    int len=res_query(dom,C_IN,ns_t_ns,ans,sizeof(ans));
    if(len<0) return 0;
    ns_msg msg; if(ns_initparse(ans,len,&msg)<0) return 0;
    int cnt=ns_msg_count(msg,ns_s_an);
    for(int i=0;i<cnt&&found<max;i++){
        ns_rr rr; if(ns_parserr(&msg,ns_s_an,i,&rr)) continue;
        dn_expand(ns_msg_base(msg),ns_msg_end(msg),
                  ns_rr_rdata(rr),out[found],MAX_DOM);
        found++;
    }
#endif
    return found;
}
 
static void print_banner(void){
#ifdef OS_WINDOWS
    HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode=0;
    if(!GetConsoleMode(h,&mode)||
       !SetConsoleMode(h,mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_color=0;
    SetConsoleOutputCP(CP_UTF8);
#endif
    printf("%s"
"⠀⠀⠀⠀  ⠀⢀⠆⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠰⡀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⢠⡏⠀⢀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⢹⣄⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⣰⡟⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⢻⣆⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⢠⣿⠁⠀⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠈⣿⡆⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⣾⡇⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⢸⣿⠀⠀⠀⠀\n"
"⠀⠀⠀⢸⣿⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⠀⣿⡇⠀⠀⠀\n"
"⠀⠀⠀⣿⣿⠀⠀⣿⣿⣧⣤⣤⣤⡀⠀⣀⠀⠀⣀⠀⢀⣤⣤⣤⣤⣤⣤⣤⣤⣼⣿⣿⠀⠀⣿⣿⠀⠀⠀\n"
"⠀⠀⢸⣿⡏⠙⢉⣉⣩⣴⣶⣤⣙⣿⣶⣯⣦⣴⣼⣷⣿⣋⣤⣶⣦⣍⣉⠉⠋⠀⢸⣿⡇\n"
"⠀⠀⢿⣿⣷⣤⣶⣶⠿⠿⠛⠋⣉⡉⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⢉⣉⠙⠛⠿⠿⣶⣶⣾⣿⡿\n"
"⠀⠀⠀⠙⠻⠋⠉⠀⠀⠀⣠⣾⡿⠟⠛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠛⠻⢿⣷⣄⠀⠀⠀⠉⠙⠟⠋\n"
"⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠋⢀⣠⣾⠟⢫⣿⣿⣿⣿⣿⣿⣿⡍⠻⣷⣄⡀⠙⠿⣷⣤⡀\n"
"⠀⠀⠀⠀⠀⣠⣴⡿⠛⠁⠀⢸⣿⣿⠋⠀⢸⣿⣿⣿⣿⣿⣿⣿⡗⠀⠙⣿⣿⡇⠀⠈⠛⢿⣦⣄\n"
"⢀⠀⣀⣴⣾⠟⠋⠀⠀⠀⠀⢸⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠙⠻⣷⣦⣀⠀⣀\n"
"⢸⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⡟\n"
"⢸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⢹⣿⣿⣿⣿⣿⡏⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇\n"
"⢸⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇\n"
"⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠈⠿⠿⠁⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿\n"
"⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟\n"
"⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃\n"
"⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⣾⠏\n"
"⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⢸⡟\n"
"⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⡾\n"
"⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⡸⠁\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⢸⡟\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⠀⠀⠀⠀⠀⠀⠀⠀⠜\n"
"\n%s", C_CYAN, C_RESET);

    printf("%s"
"  [*] Made & Develomoent By RussianHarvey\n"
"  [*] Discord UserName : russianharvey \n"
"  [*] For authorized security assessments only\n"
"  [*] Unauthorized use is illegal and unethical\n"
"  [*] Always obtain written permission before scanning\n\n"
"%s", C_DIM, C_RESET);
}


static void scan_dns(const char *dom){
    section("DNS RECORDS");
    int total=0;
 
#ifdef OS_WINDOWS
    static const struct{WORD t;const char*l;}T[]={
        {DNS_TYPE_A,"A"},{DNS_TYPE_AAAA,"AAAA"},{DNS_TYPE_MX,"MX"},
        {DNS_TYPE_NS,"NS"},{DNS_TYPE_TXT,"TXT"},{DNS_TYPE_SOA,"SOA"},
        {DNS_TYPE_CNAME,"CNAME"},{DNS_TYPE_CAA,"CAA"},
    };
    for(int t=0;t<(int)(sizeof(T)/sizeof(T[0]));t++){
        PDNS_RECORD pr=NULL;
        if(DnsQuery_A(dom,T[t].t,DNS_QUERY_STANDARD,NULL,&pr,NULL)!=ERROR_SUCCESS) continue;
        for(PDNS_RECORD r=pr;r;r=r->pNext){
            if(r->wType!=T[t].t) continue;
            char v[512]={0};
            switch(r->wType){
            case DNS_TYPE_A:{struct in_addr in;in.s_addr=r->Data.A.IpAddress;inet_ntop(AF_INET,&in,v,sizeof(v));break;}
            case DNS_TYPE_AAAA: inet_ntop(AF_INET6,&r->Data.AAAA.Ip6Address,v,sizeof(v));break;
            case DNS_TYPE_MX:  snprintf(v,sizeof(v),"pri=%u %s",r->Data.MX.wPreference,r->Data.MX.pNameExchange);break;
            case DNS_TYPE_NS:  snprintf(v,sizeof(v),"%s",r->Data.NS.pNameHost);break;
            case DNS_TYPE_CNAME:snprintf(v,sizeof(v),"%s",r->Data.CNAME.pNameHost);break;
            case DNS_TYPE_TXT:
                for(DWORD i=0;i<r->Data.TXT.dwStringCount;i++)
                    strncat(v,r->Data.TXT.pStringArray[i],sizeof(v)-strlen(v)-1);
                break;
            case DNS_TYPE_SOA: snprintf(v,sizeof(v),"mname=%s serial=%lu",r->Data.SOA.pNamePrimaryServer,(unsigned long)r->Data.SOA.dwSerialNo);break;
            default: snprintf(v,sizeof(v),"(type %u)",r->wType);
            }
            if(v[0]){LOK("%s%-8s%s : %s",C_BOLD,T[t].l,C_RESET,v);total++;}
        }
        DnsRecordListFree(pr,DnsFreeRecordList);
    }
    /* DMARC */
    char dq[MAX_DOM]; snprintf(dq,sizeof(dq),"_dmarc.%s",dom);
    PDNS_RECORD pr2=NULL;
    if(DnsQuery_A(dq,DNS_TYPE_TEXT,DNS_QUERY_STANDARD,NULL,&pr2,NULL)==ERROR_SUCCESS){
        for(PDNS_RECORD r=pr2;r;r=r->pNext){
            if(r->wType!=DNS_TYPE_TEXT) continue;
            char v[512]={0};
            for(DWORD i=0;i<r->Data.TXT.dwStringCount;i++)
                strncat(v,r->Data.TXT.pStringArray[i],sizeof(v)-strlen(v)-1);
            if(v[0]){LOK("%sDMARC   %s : %.100s",C_BOLD,C_RESET,v);total++;}
        }
        DnsRecordListFree(pr2,DnsFreeRecordList);
    }
#else
    static const struct{int t;const char*l;}T[]={
        {ns_t_a,"A"},{ns_t_aaaa,"AAAA"},{ns_t_mx,"MX"},{ns_t_ns,"NS"},
        {ns_t_txt,"TXT"},{ns_t_soa,"SOA"},{ns_t_cname,"CNAME"},{ns_t_caa,"CAA"},
    };
    for(int ti=0;ti<(int)(sizeof(T)/sizeof(T[0]));ti++){
        unsigned char ans[NS_MAXMSG];
        int len=res_query(dom,C_IN,T[ti].t,ans,sizeof(ans));
        if(len<0) continue;
        ns_msg msg; if(ns_initparse(ans,len,&msg)<0) continue;
        int cnt=ns_msg_count(msg,ns_s_an);
        for(int i=0;i<cnt;i++){
            ns_rr rr; if(ns_parserr(&msg,ns_s_an,i,&rr)) continue;
            char v[NS_MAXDNAME*2]={0};
            switch(ns_rr_type(rr)){
            case ns_t_a:{struct in_addr in;memcpy(&in,ns_rr_rdata(rr),4);inet_ntop(AF_INET,&in,v,sizeof(v));break;}
            case ns_t_aaaa: inet_ntop(AF_INET6,ns_rr_rdata(rr),v,sizeof(v));break;
            case ns_t_mx:{char nm[NS_MAXDNAME];dn_expand(ns_msg_base(msg),ns_msg_end(msg),ns_rr_rdata(rr)+2,nm,sizeof(nm));snprintf(v,sizeof(v),"pri=%d %s",ns_get16(ns_rr_rdata(rr)),nm);break;}
            case ns_t_ns: case ns_t_cname: dn_expand(ns_msg_base(msg),ns_msg_end(msg),ns_rr_rdata(rr),v,sizeof(v));break;
            case ns_t_txt:{const unsigned char*rd=ns_rr_rdata(rr);int rl=(int)ns_rr_rdlen(rr),of=0;size_t bo=0;while(of<rl&&bo<sizeof(v)-2){int sl=rd[of++];int cp=sl<rl-of?sl:rl-of;if((int)(sizeof(v)-bo-1)<cp)cp=(int)(sizeof(v)-bo-1);memcpy(v+bo,rd+of,(size_t)cp);bo+=(size_t)cp;of+=cp;}break;}
            case ns_t_soa:{char mn[NS_MAXDNAME],rn[NS_MAXDNAME];int n=dn_expand(ns_msg_base(msg),ns_msg_end(msg),ns_rr_rdata(rr),mn,sizeof(mn));dn_expand(ns_msg_base(msg),ns_msg_end(msg),ns_rr_rdata(rr)+n,rn,sizeof(rn));snprintf(v,sizeof(v),"mname=%s rname=%s",mn,rn);break;}
            default: snprintf(v,sizeof(v),"(type %d)",ns_rr_type(rr));
            }
            if(v[0]){LOK("%s%-8s%s : %s",C_BOLD,T[ti].l,C_RESET,v);total++;}
        }
    }
    char dq[MAX_DOM]; snprintf(dq,sizeof(dq),"_dmarc.%s",dom);
    char dt[BUF_M]; dns_txt(dq,dt,sizeof(dt));
    if(dt[0]){LOK("%sDMARC   %s : %.120s",C_BOLD,C_RESET,dt);total++;}
#endif
 
    if(!total) LERR("No DNS records retrieved");
 
    /* Wildcard test */
    char rq[MAX_DOM],wip[64]={0};
    snprintf(rq,sizeof(rq),"xwt%09ld.%s",(long)time(NULL),dom);
    if(dns_a(rq,wip,sizeof(wip))==0)
        LWARN("%s[WILDCARD DNS]%s All subdomains resolve!",C_RED,C_RESET);
    else
        LOK("No wildcard DNS detected");
}
 
/* ============================================================
 * 2. IP INFO
 * ============================================================ */
static void scan_ip(const char *dom){
    section("IP ADDRESS & NETWORK INFO");
    g_ip[0]=g_org[0]=g_country[0]='\0';
 
    if(dns_a(dom,g_ip,sizeof(g_ip))!=0){LERR("Cannot resolve: %s",dom);return;}
    LOK("IPv4 Address   : %s%s%s%s",C_BOLD,C_GREEN,g_ip,C_RESET);
 
    /* IPv6 */
    struct addrinfo h={0},*r=NULL;
    h.ai_family=AF_INET6; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(dom,NULL,&h,&r)==0){
        char ip6[64];
        inet_ntop(AF_INET6,&((struct sockaddr_in6*)r->ai_addr)->sin6_addr,ip6,sizeof(ip6));
        LOK("IPv6 Address   : %s%s%s",C_BOLD,ip6,C_RESET);
        freeaddrinfo(r);
    }
 
    /* rDNS */
    struct sockaddr_in sa={0};
    sa.sin_family=AF_INET; inet_pton(AF_INET,g_ip,&sa.sin_addr);
    char host[NI_MAXHOST];
    if(getnameinfo((struct sockaddr*)&sa,sizeof(sa),host,sizeof(host),NULL,0,NI_NAMEREQD)==0)
        LOK("PTR (rDNS)     : %s",host);
    else LWARN("No PTR record found");
 
    /* ipinfo.io */
    char *buf=(char*)calloc(1,BUF_L);
    if(buf){
        char p[64]; snprintf(p,sizeof(p),"/%s/json",g_ip);
        if(http_get("ipinfo.io",80,p,buf,(size_t)BUF_L)>0){
            char org[128]={0},ctr[64]={0},city[64]={0},reg[64]={0},tz[64]={0},loc[32]={0};
            json_get(buf,"org",org,sizeof(org));
            json_get(buf,"country",ctr,sizeof(ctr));
            json_get(buf,"city",city,sizeof(city));
            json_get(buf,"region",reg,sizeof(reg));
            json_get(buf,"timezone",tz,sizeof(tz));
            json_get(buf,"loc",loc,sizeof(loc));
            strncpy(g_org,org,sizeof(g_org)-1);
            strncpy(g_country,ctr,sizeof(g_country)-1);
            if(org[0]) LOK("Organization   : %s%s%s",C_BOLD,org,C_RESET);
            if(ctr[0]) LOK("Location       : %s | %s, %s",ctr,reg,city);
            if(loc[0]) LOK("Coordinates    : %s",loc);
            if(tz[0])  LOK("Timezone       : %s",tz);
            /* CDN check */
            char ol[128]={0}; strncpy(ol,org,sizeof(ol)-1); s_lower(ol);
            static const char *ck[]={"cloudflare","akamai","fastly","amazon","google","azure",NULL};
            static const char *cn[]={"Cloudflare","Akamai","Fastly","AWS CloudFront","Google CDN","Azure CDN"};
            for(int i=0;ck[i];i++) if(strstr(ol,ck[i])){LINFO("CDN/Proxy      : %s%s%s -- real IP may differ",C_YELLOW,cn[i],C_RESET);break;}
        }
        /* Shodan InternetDB */
        char sp[64]; snprintf(sp,sizeof(sp),"/%s",g_ip);
        memset(buf,0,BUF_L);
        if(http_get("internetdb.shodan.io",80,sp,buf,(size_t)BUF_L)>0){
            char *ps=strstr(buf,"\"ports\":[");
            if(ps){char pb[512]={0};char*s=ps+9,*e=strchr(s,']');if(e&&e>s){size_t l=(size_t)(e-s);if(l>=sizeof(pb))l=sizeof(pb)-1;memcpy(pb,s,l);pb[l]='\0';if(pb[0])LOK("Shodan Ports   : %s%s%s",C_BOLD,pb,C_RESET);}}
            char *vs=strstr(buf,"\"vulns\":[");
            if(vs){char vb[1024]={0};char*s=vs+9,*e=strchr(s,']');if(e&&e>s){size_t l=(size_t)(e-s);if(l>=sizeof(vb))l=sizeof(vb)-1;memcpy(vb,s,l);vb[l]='\0';if(vb[0])LVULN("Known CVEs     : %s",vb);}}
        }
        free(buf);
    }
}
 
/* ============================================================
 * 3. WHOIS
 * ============================================================ */
static void scan_whois(const char *dom){
    section("WHOIS INFORMATION");
    char iana[BUF_M]={0};
    whois_q("whois.iana.org",dom,iana,sizeof(iana));
    char ws[256]="whois.verisign-grs.com";
    const char *tags[]={"refer:","whois:",NULL};
    for(int t=0;tags[t];t++){
        char *p=strcasestr(iana,tags[t]); if(!p) continue;
        p+=strlen(tags[t]); while(*p==' ')p++;
        char *e=strpbrk(p,"\r\n");
        if(e){size_t l=(size_t)(e-p);if(l<sizeof(ws)){memcpy(ws,p,l);ws[l]='\0';s_trim(ws);}}
        break;
    }
    LINFO("Querying: %s",ws);
    char *buf=(char*)calloc(1,65536);
    if(!buf) return;
    if(whois_q(ws,dom,buf,65536)<=0){LERR("WHOIS query failed");free(buf);return;}
 
    static const char *F[]={
        "Registrar:","Creation Date:","Registry Expiry Date:",
        "Updated Date:","Domain Status:","Name Server:",
        "Registrant Organization:","Registrant Country:",
        "Registrant Email:","Registrar Abuse Contact Email:",NULL
    };
    for(int i=0;F[i];i++){
        char *p=buf; int sh=0;
        while((p=strcasestr(p,F[i]))!=NULL&&sh<3){
            p+=strlen(F[i]); while(*p==' ')p++;
            char v[512]={0}; char *e=strpbrk(p,"\r\n");
            if(e){size_t l=(size_t)(e-p);if(l<sizeof(v)){memcpy(v,p,l);v[l]='\0';}}
            s_trim(v); if(v[0]){LOK("%-35s %s",F[i],v);sh++;} p++;
        }
    }
    char *cd=strcasestr(buf,"Creation Date:");
    if(cd){cd+=14;while(*cd==' ')cd++;
        int yr=0,mo=0,dy=0;
        if(sscanf(cd,"%d-%d-%d",&yr,&mo,&dy)==3&&yr>1990){
            struct tm t={0};t.tm_year=yr-1900;t.tm_mon=mo-1;t.tm_mday=dy;
            double ad=difftime(time(NULL),mktime(&t))/86400.0;
            if(ad<30)      LVULN("Domain Age: %.0f days -- VERY NEW, HIGH PHISHING RISK!",ad);
            else if(ad<90) LWARN("Domain Age     : %.0f days %s(new)%s",ad,C_YELLOW,C_RESET);
            else           LOK("Domain Age     : %.1f years (%d days) %s%s",ad/365.0,(int)ad,C_GREEN,C_RESET);
        }
    }
    if(strcasestr(buf,"privacy")||strcasestr(buf,"redacted")||
       strcasestr(buf,"whoisguard")||strcasestr(buf,"proxy"))
        LINFO("WHOIS Privacy  : Protection service detected");
    free(buf);
}
 
/* ============================================================
 * 4. PORT SCAN
 * ============================================================ */
typedef struct { char ip[64]; int port; const char *svc; const char *risk; int open; } PortJob;
 
static thr_ret THR_CALL port_worker(void *arg){
    PortJob *j=(PortJob*)arg;
    SOCK_T s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==BADSOCK) return 0;
    struct sockaddr_in a={0};
    a.sin_family=AF_INET; a.sin_port=htons((unsigned short)j->port);
    inet_pton(AF_INET,j->ip,&a.sin_addr);
    if(nb_connect(s,(struct sockaddr*)&a,sizeof(a),T_PORT_MS)==0) j->open=1;
    CLOSESOCK(s); return 0;
}
 
static void scan_ports(const char *ip){
    section("PORT SCAN (Common Services)");
    if(!ip||!*ip){LERR("No IP to scan");return;}
    static const struct{int p;const char*s;const char*r;}P[]={
        {21,"FTP","CRITICAL"},{22,"SSH","MEDIUM"},{23,"Telnet","CRITICAL"},
        {25,"SMTP","MEDIUM"},{53,"DNS","MEDIUM"},{80,"HTTP","LOW"},
        {110,"POP3","MEDIUM"},{135,"RPC","HIGH"},{139,"NetBIOS","HIGH"},
        {143,"IMAP","MEDIUM"},{161,"SNMP","HIGH"},{389,"LDAP","HIGH"},
        {443,"HTTPS","LOW"},{445,"SMB","CRITICAL"},{465,"SMTPS","LOW"},
        {587,"SMTP-TLS","LOW"},{636,"LDAPS","MEDIUM"},{993,"IMAPS","LOW"},
        {995,"POP3S","LOW"},{1433,"MSSQL","CRITICAL"},{1521,"Oracle","CRITICAL"},
        {2222,"SSH-Alt","MEDIUM"},{2375,"Docker-HTTP","CRITICAL"},
        {2376,"Docker-TLS","HIGH"},{2379,"etcd","CRITICAL"},
        {3000,"Dev-Server","MEDIUM"},{3306,"MySQL","CRITICAL"},
        {3389,"RDP","CRITICAL"},{5432,"PostgreSQL","CRITICAL"},
        {5672,"AMQP","HIGH"},{5900,"VNC","CRITICAL"},{5984,"CouchDB","HIGH"},
        {6379,"Redis","CRITICAL"},{6443,"K8s-API","CRITICAL"},
        {8000,"HTTP-Dev","MEDIUM"},{8080,"HTTP-Alt","MEDIUM"},
        {8443,"HTTPS-Alt","MEDIUM"},{8888,"Jupyter","HIGH"},
        {9092,"Kafka","HIGH"},{9200,"Elasticsearch","HIGH"},
        {9300,"ES-Cluster","HIGH"},{10250,"Kubelet","CRITICAL"},
        {27017,"MongoDB","CRITICAL"},{27018,"MongoDB-Alt","CRITICAL"},
    };
    int n=(int)(sizeof(P)/sizeof(P[0]));
    PortJob  *jobs=(PortJob*)calloc((size_t)n,sizeof(PortJob));
    thr_t    *tids=(thr_t*)calloc((size_t)n,sizeof(thr_t));
    LINFO("Scanning %d ports on %s ...",n,ip);
    for(int i=0;i<n;i++){
        strncpy(jobs[i].ip,ip,63); jobs[i].port=P[i].p;
        jobs[i].svc=P[i].s; jobs[i].risk=P[i].r;
        thr_create(&tids[i],port_worker,&jobs[i]);
    }
    int oc=0;
    for(int i=0;i<n;i++){
        thr_join(tids[i]); thr_close(tids[i]);
        if(!jobs[i].open) continue; oc++;
        const char *col=C_GREEN;
        if(!strcmp(jobs[i].risk,"CRITICAL"))col=C_RED;
        else if(!strcmp(jobs[i].risk,"HIGH"))col=C_YELLOW;
        LOK("Port %-6d %-22s %s%s[%s]%s",
            jobs[i].port,jobs[i].svc,col,C_BOLD,jobs[i].risk,C_RESET);
    }
    if(!oc) LWARN("No common ports open (firewall may block probes)");
    else    LINFO("Total open: %d port(s)",oc);
    free(jobs); free(tids);
}
 
/* ============================================================
 * 5. HTTP HEADERS
 * ============================================================ */
static void scan_http(const char *dom){
    section("HTTP HEADERS & SECURITY ANALYSIS");
    char *buf=(char*)calloc(1,BUF_XL);
    if(!buf) return;
    if(http_get(dom,80,"/",buf,(size_t)BUF_XL)<=0){
        LWARN("HTTP port 80 not responding"); free(buf); return;
    }
    char st[64]={0}; sscanf(buf,"HTTP/%*s %63[^\r\n]",st);
    LOK("HTTP Status    : %s%s%s",C_BOLD,st,C_RESET);
 
    static const struct{const char*h;const char*l;}SH[]={
        {"Server:","Server"},{"X-Powered-By:","X-Powered-By"},
        {"Content-Type:","Content-Type"},{"Location:","Redirect"},
        {"Via:","Via (proxy)"},{"CF-Ray:","Cloudflare-Ray"},
        {"X-Cache:","X-Cache"},{"Set-Cookie:","Cookie"},{NULL,NULL}
    };
    for(int i=0;SH[i].h;i++){
        char *p=strcasestr(buf,SH[i].h); if(!p) continue;
        p+=strlen(SH[i].h); while(*p==' ')p++;
        char v[512]={0}; char *e=strpbrk(p,"\r\n");
        if(e){size_t l=(size_t)(e-p);if(l<sizeof(v)){memcpy(v,p,l);v[l]='\0';}}
        LOK("%-16s : %s",SH[i].l,v);
    }
 
    /* Tech fingerprint */
    char *bl=(char*)calloc(1,BUF_XL);
    if(bl){
        memcpy(bl,buf,BUF_XL); s_lower(bl);
        static const char *tk[]={"wordpress","drupal","joomla","nginx","apache","iis","cloudflare","express","django","laravel","php","asp.net","jquery","react","vue","bootstrap",NULL};
        static const char *tn[]={"WordPress","Drupal","Joomla","Nginx","Apache","IIS","Cloudflare","Express.js","Django","Laravel","PHP","ASP.NET","jQuery","React","Vue.js","Bootstrap",NULL};
        char det[512]={0};
        for(int i=0;tk[i];i++)
            if(strstr(bl,tk[i])){if(det[0])strncat(det,", ",sizeof(det)-strlen(det)-1);strncat(det,tn[i],sizeof(det)-strlen(det)-1);}
        if(det[0]) LOK("Detected Tech  : %s%s%s",C_BOLD,det,C_RESET);
        free(bl);
    }
 
    /* Security headers */
    printf("\n  %sSecurity Headers Check:%s\n",C_YELLOW,C_RESET);
    static const struct{const char*h;const char*d;}SEC[]={
        {"Strict-Transport-Security","Protects against HTTPS downgrade"},
        {"Content-Security-Policy","Mitigates XSS and data injection"},
        {"X-Frame-Options","Prevents clickjacking attacks"},
        {"X-Content-Type-Options","Prevents MIME type sniffing"},
        {"Referrer-Policy","Controls referrer info leakage"},
        {"Permissions-Policy","Controls browser feature access"},
        {"X-XSS-Protection","Legacy XSS filter (deprecated)"},
        {"Cross-Origin-Embedder-Policy","Cross-origin isolation"},
        {"Cross-Origin-Opener-Policy","Cross-origin opener control"},
        {NULL,NULL}
    };
    int present=0,tot=0;
    for(int i=0;SEC[i].h;i++){
        tot++;
        char sr[128]; snprintf(sr,sizeof(sr),"%s:",SEC[i].h);
        if(strcasestr(buf,sr)){printf("    %s[PRESENT]%s %s\n",C_GREEN,C_RESET,SEC[i].h);present++;}
        else printf("    %s[MISSING]%s %s -- %s%s%s\n",C_RED,C_RESET,SEC[i].h,C_DIM,SEC[i].d,C_RESET);
    }
    int sc=(present*100)/tot;
    const char *col=sc>=70?C_GREEN:sc>=40?C_YELLOW:C_RED;
    printf("\n  %sSecurity Score: %s%d%%%s (%d/%d headers present)\n",
           C_BOLD,col,sc,C_RESET,present,tot);
    free(buf);
}
 
/* ============================================================
 * 6. EMAIL SECURITY
 * ============================================================ */
static void scan_email(const char *dom){
    section("EMAIL SECURITY (SPF / DMARC / DKIM / MTA-STS)");
 
    /* SPF */
    char sb[BUF_M]={0}; dns_txt(dom,sb,sizeof(sb));
    char *spf=strcasestr(sb,"v=spf");
    if(spf){
        char ln[512]={0}; char *e=strpbrk(spf,"\n");if(!e)e=spf+strlen(spf);
        size_t l=(size_t)(e-spf);if(l>=sizeof(ln))l=sizeof(ln)-1;
        memcpy(ln,spf,l);ln[l]='\0';
        LOK("SPF Record     : %.100s",ln);
        if(strstr(ln,"+all"))     LVULN("SPF +all -- DANGEROUS! Any server can spoof domain!");
        else if(strstr(ln,"-all"))LOK("SPF Policy     : -all HardFail %s(fully enforced)%s",C_GREEN,C_RESET);
        else if(strstr(ln,"~all"))LWARN("SPF Policy     : ~all SoftFail (not fully enforced)");
        else if(strstr(ln,"?all"))LWARN("SPF Policy     : ?all Neutral (no enforcement)");
    } else LVULN("No SPF record -- domain can be spoofed for phishing!");
 
    /* DMARC */
    char dq[MAX_DOM]; snprintf(dq,sizeof(dq),"_dmarc.%s",dom);
    char db[BUF_M]={0}; dns_txt(dq,db,sizeof(db));
    char *dm=strcasestr(db,"v=dmarc");
    if(dm){
        char ln[512]={0}; char *e=strpbrk(dm,"\n");if(!e)e=dm+strlen(dm);
        size_t l=(size_t)(e-dm);if(l>=sizeof(ln))l=sizeof(ln)-1;
        memcpy(ln,dm,l);ln[l]='\0';
        LOK("DMARC Record   : %.100s",ln);
        if(strstr(ln,"p=reject"))        LOK("DMARC Policy   : reject -- Maximum protection %s",C_GREEN);
        else if(strstr(ln,"p=quarantine"))LWARN("DMARC Policy   : quarantine -- Moderate protection");
        else if(strstr(ln,"p=none"))      LWARN("DMARC Policy   : none -- Monitoring only, NO protection!");
    } else LVULN("No DMARC record -- emails bypass authentication!");
 
    /* DKIM */
    static const char *sels[]={"default","google","mail","email","k1","k2",
        "selector1","selector2","sig1","dkim","s1","s2","smtp","ses",
        "sendgrid","mailjet","zoho",NULL};
    int df=0;
    for(int i=0;sels[i]&&!df;i++){
        char dkq[MAX_DOM]; snprintf(dkq,sizeof(dkq),"%s._domainkey.%s",sels[i],dom);
        char dkb[BUF_M]={0}; dns_txt(dkq,dkb,sizeof(dkb));
        if(dkb[0]){LOK("DKIM Selector  : '%s' found %s",sels[i],C_GREEN);df=1;}
    }
    if(!df) LWARN("DKIM: No common selectors found");
 
    /* MTA-STS */
    char mh[MAX_DOM]; snprintf(mh,sizeof(mh),"mta-sts.%s",dom);
    char mb[BUF_M]={0};
    if(http_get(mh,80,"/.well-known/mta-sts.txt",mb,sizeof(mb))>0&&strstr(mb,"version:"))
        LOK("MTA-STS        : Policy found -- enforces TLS %s",C_GREEN);
    else
        LINFO("MTA-STS        : Not configured (optional)");
}
 
/* ============================================================
 * 7. SUBDOMAIN ENUMERATION
 * ============================================================ */
typedef struct { char dom[MAX_DOM]; char sub[64]; char ip[64]; int found; } SubJob;
 
static thr_ret THR_CALL sub_worker(void *arg){
    SubJob *j=(SubJob*)arg;
    char full[MAX_DOM]; snprintf(full,sizeof(full),"%s.%s",j->sub,j->dom);
    j->found=(dns_a(full,j->ip,sizeof(j->ip))==0);
    return 0;
}
 
static void scan_subs(const char *dom){
    section("SUBDOMAIN ENUMERATION");
    static const char *subs[]={
        "www","mail","ftp","admin","blog","shop","api","dev","test",
        "vpn","remote","secure","webmail","cpanel","ns1","ns2","ns3",
        "mx","mx1","mx2","smtp","pop3","imap","cloud","backup","git",
        "wiki","docs","status","monitor","proxy","portal","dashboard",
        "app","cdn","static","media","img","assets","support","help",
        "login","auth","sso","oauth","uat","staging","demo","beta",
        "sandbox","preview","qa","old","legacy","v1","v2","v3","new",
        "db","sql","mysql","postgres","redis","jenkins","ci","cd",
        "jira","confluence","gitlab","docker","k8s","registry",
        "panel","controlpanel","cp","whm","plesk","api2","rest",
        "graphql","ws","autodiscover","exchange","owa","intranet",
        "internal","corp","us","eu","uk","de","fr","files","sftp",
        "smtp2","mail2","imap2","relay","mx3","s3","upload",NULL
    };
    int n=0; while(subs[n])n++;
    SubJob *jobs=(SubJob*)calloc((size_t)n,sizeof(SubJob));
    thr_t  *tids=(thr_t*)calloc((size_t)n,sizeof(thr_t));
    LINFO("Checking %d common subdomains...",n);
    for(int i=0;i<n;i++){
        strncpy(jobs[i].dom,dom,MAX_DOM-1);
        strncpy(jobs[i].sub,subs[i],63);
        thr_create(&tids[i],sub_worker,&jobs[i]);
    }
    int cnt=0;
    for(int i=0;i<n;i++){
        thr_join(tids[i]); thr_close(tids[i]);
        if(!jobs[i].found) continue; cnt++;
        char full[MAX_DOM]; snprintf(full,sizeof(full),"%s.%s",jobs[i].sub,dom);
        LOK("%-45s -> %s%s%s",full,C_BOLD,jobs[i].ip,C_RESET);
    }
    free(jobs); free(tids);
 
    /* crt.sh CT logs */
    printf("\n  %s[*]%s Checking Certificate Transparency (crt.sh)...\n",C_CYAN,C_RESET);
    char *ctb=(char*)calloc(1,BUF_XL);
    if(ctb){
        char cp[MAX_DOM+64]; snprintf(cp,sizeof(cp),"/?q=%%.%s&output=json",dom);
        if(http_get("crt.sh",80,cp,ctb,(size_t)BUF_XL)>0){
            int e=0; char *p=ctb;
            while((p=strstr(p,"\"name_value\""))!=NULL){e++;p++;}
            LOK("CT Logs        : ~%d certificate entries found",e);
        }
        free(ctb);
    }
    LINFO("Full CT list   : https://crt.sh/?q=%%.%s",dom);
    if(!cnt) LWARN("No subdomains resolved");
    else     LINFO("Total found    : %s%d%s subdomains",C_BOLD,cnt,C_RESET);
}
 
/* ============================================================
 * 8. TECH FINGERPRINTING
 * ============================================================ */
static void scan_fp(const char *dom){
    section("TECHNOLOGY FINGERPRINTING");
    static const struct{const char*path;const char*lbl;int crit;}PR[]={
        {"/.git/HEAD",                 "GIT REPO EXPOSED",        1},
        {"/.env",                      ".ENV FILE EXPOSED",        1},
        {"/phpinfo.php",               "PHPinfo EXPOSED",          1},
        {"/server-status",             "Apache Server-Status",     1},
        {"/actuator/env",              "Spring Boot Env EXPOSED",  1},
        {"/adminer.php",               "Adminer DB Tool",          1},
        {"/phpmyadmin/",               "phpMyAdmin",               1},
        {"/wp-login.php",              "WordPress",                0},
        {"/wp-admin/",                 "WordPress Admin",          0},
        {"/administrator/",            "Joomla",                   0},
        {"/user/login",                "Drupal",                   0},
        {"/admin",                     "Admin Panel",              0},
        {"/jenkins",                   "Jenkins CI",               0},
        {"/robots.txt",                "robots.txt",               0},
        {"/sitemap.xml",               "sitemap.xml",              0},
        {"/.well-known/security.txt",  "security.txt",             0},
        {NULL,NULL,0}
    };
    char *buf=(char*)calloc(1,BUF_M);
    if(!buf) return;
    for(int i=0;PR[i].path;i++){
        memset(buf,0,BUF_M);
        if(http_get(dom,80,PR[i].path,buf,(size_t)BUF_M)<=0) continue;
        int code=0; sscanf(buf,"HTTP/%*s %d",&code);
        if(code==200){
            if(PR[i].crit) LVULN("EXPOSED [200]: %s  ->  %s",PR[i].path,PR[i].lbl);
            else            LOK("Found  [200]: %s  ->  %s",PR[i].path,PR[i].lbl);
        } else if(code==403){
            LWARN("Forbidden [403]: %s -> %s (exists but blocked)",PR[i].path,PR[i].lbl);
        }
    }
    free(buf);
}
 
/* ============================================================
 * 9. ZONE TRANSFER
 * ============================================================ */
static void scan_zone(const char *dom){
    section("DNS ZONE TRANSFER TEST");
    char ns[MAX_NS][MAX_DOM] = {{0}};
    int nc=dns_ns(dom,ns,MAX_NS);
    if(!nc){LERR("Could not retrieve NS records");return;}
    for(int i=0;i<nc;i++){
        char nsip[64]={0};
        if(dns_a(ns[i],nsip,sizeof(nsip))!=0){LWARN("Cannot resolve NS: %s",ns[i]);continue;}
        SOCK_T s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s==BADSOCK) continue;
        struct sockaddr_in srv={0};
        srv.sin_family=AF_INET; srv.sin_port=htons(53);
        inet_pton(AF_INET,nsip,&srv.sin_addr);
        if(nb_connect(s,(struct sockaddr*)&srv,sizeof(srv),5000)!=0){
            CLOSESOCK(s); LOK("Zone transfer blocked: %s (TCP refused)",ns[i]); continue;
        }
        /* Build AXFR query */
        unsigned char pkt[512]={0},dq[512]={0};
        unsigned short txid = htons((unsigned short)rand());
        memcpy(dq,&txid,2); dq[5]=1;
        int off=12;
        const char *lb=dom;
        for(;;){
            const char *dot=strchr(lb,'.');
            int ll=dot?(int)(dot-lb):(int)strlen(lb);
            dq[off++]=(unsigned char)ll;
            memcpy(dq+off,lb,(size_t)ll); off+=ll;
            if(!dot) break; lb=dot+1;
        }
        dq[off++]=0; dq[off++]=0; dq[off++]=0xFC;
        dq[off++]=0; dq[off++]=1;
        unsigned short ql = htons((unsigned short)off);
        memcpy(pkt,&ql,2); memcpy(pkt+2,dq,(size_t)off);
        send(s,(char*)pkt,off+2,0);
        unsigned char resp[65536]; int rl=(int)recv(s,(char*)resp,sizeof(resp),0);
        CLOSESOCK(s);
        if(rl>6&&!(resp[3]&0x0F)&&(resp[4]||resp[5]||resp[6]||resp[7]))
            LVULN("ZONE TRANSFER ALLOWED on %s -- CRITICAL MISCONFIGURATION!",ns[i]);
        else
            LOK("Zone transfer blocked: %s",ns[i]);
    }
}
 
/* ============================================================
 * 10. SUMMARY + JSON REPORT
 * ============================================================ */
static void print_summary(const char *dom, double elapsed){
    section("SECURITY ASSESSMENT SUMMARY");
    time_t now=time(NULL);
    char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",localtime(&now));
    printf("\n  %s%s%s\n",C_BOLD,
           "──────────────────────────────────────────────────────",C_RESET);
    printf("  %sTarget    :%s %s%s%s\n",C_BOLD,C_RESET,C_CYAN,dom,C_RESET);
    printf("  %sIP        :%s %s\n",C_BOLD,C_RESET,g_ip[0]?g_ip:"Unknown");
    printf("  %sOrg       :%s %s\n",C_BOLD,C_RESET,g_org[0]?g_org:"Unknown");
    printf("  %sCountry   :%s %s\n",C_BOLD,C_RESET,g_country[0]?g_country:"Unknown");
    printf("  %sScan Time :%s %s\n",C_BOLD,C_RESET,ts);
    printf("  %sDuration  :%s %.1f seconds\n",C_BOLD,C_RESET,elapsed);
    printf("  %s%s%s\n\n",C_BOLD,
           "──────────────────────────────────────────────────────",C_RESET);
    printf("  %s[*]%s Review each section above for detailed findings.\n",C_CYAN,C_RESET);
    printf("  %s%s[VULN]%s markers require immediate attention.\n",C_RED,C_BOLD,C_RESET);
    printf("  %s[*]%s Report saved in osint_reports/ directory.\n",C_CYAN,C_RESET);
    printf("\n  %sCopyright (c) 2025 RussianHarvey%s\n",C_DIM,C_RESET);
}
 
static void save_report(const char *dom, double elapsed){
    MKDIR("osint_reports");
    char safe[MAX_DOM]; strncpy(safe,dom,sizeof(safe)-1);
    for(char *p=safe;*p;p++) if(*p=='.') *p='_';
    char path[512];
    snprintf(path,sizeof(path),"osint_reports/osint_%s_%ld.json",safe,(long)time(NULL));
    FILE *f=fopen(path,"w");
    if(!f){LWARN("Cannot save report: %s",path);return;}
    time_t now=time(NULL);
    char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%dT%H:%M:%S",localtime(&now));
    fprintf(f,
        "{\n"
        "  \"tool\":      \"Domain OSINT v10.0\",\n"
        "  \"author\":    \"RussianHarvey\",\n"
        "  \"domain\":    \"%s\",\n"
        "  \"ip\":        \"%s\",\n"
        "  \"org\":       \"%s\",\n"
        "  \"country\":   \"%s\",\n"
        "  \"timestamp\": \"%s\",\n"
        "  \"duration\":  %.2f\n"
        "}\n",
        dom,g_ip,g_org,g_country,ts,elapsed);
    fclose(f);
    LOK("Report saved   : %s%s%s",C_BOLD,path,C_RESET);
}
 
/* ============================================================
 * MAIN SCAN
 * ============================================================ */
static void run_scan(const char *dom, int skip_ports){
    printf("\n%s%s  ► Target: %s%s\n\n",C_RED,C_BOLD,dom,C_RESET);
    double start=now_s();
    scan_ip(dom);
    scan_dns(dom);
    scan_whois(dom);
    scan_http(dom);
    scan_subs(dom);
    scan_email(dom);
    if(!skip_ports) scan_ports(g_ip);
    else            LWARN("Port scan skipped");
    scan_zone(dom);
    scan_fp(dom);
    double elapsed=now_s()-start;
    print_summary(dom,elapsed);
    save_report(dom,elapsed);
    printf("\n%s%s  [✓] Scan complete in %.1f seconds%s\n",C_GREEN,C_BOLD,elapsed,C_RESET);
}
 
/* ============================================================
 * ENTRY POINT
 * ============================================================ */
static void usage(const char *p){
    printf(
    "Domain OSINT v10.0 -- Copyright (c) 2025 RussianHarvey\n\n"
    "Usage:\n"
    "  %s                        Interactive mode\n"
    "  %s -d <domain>            Scan single domain\n"
    "  %s -d <domain> --no-ports Skip port scan\n"
    "  %s --batch <file>         Scan from file (one domain per line)\n\n"
    "Build (Windows MinGW):\n"
    "  gcc -O2 -o domain_osint.exe domain_osint.c -lws2_32 -ldnsapi\n\n"
    "Build (Linux):\n"
    "  gcc -O2 -o domain_osint domain_osint.c -lresolv -lpthread\n",
    p,p,p,p);
}
 
int main(int argc, char *argv[]){
    srand((unsigned)time(NULL));
    net_init();
    print_banner();
 
    const char *target=NULL, *batch=NULL;
    int skip_ports=0;
    for(int i=1;i<argc;i++){
        if((!strcmp(argv[i],"-d")||!strcmp(argv[i],"--domain"))&&i+1<argc) target=argv[++i];
        else if(!strcmp(argv[i],"--no-ports")) skip_ports=1;
        else if((!strcmp(argv[i],"--batch")||!strcmp(argv[i],"-b"))&&i+1<argc) batch=argv[++i];
        else if(!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help")){usage(argv[0]);net_cleanup();return 0;}
    }
 
    if(batch){
        FILE *f=fopen(batch,"r");
        if(!f){fprintf(stderr,"%s[-]%s Cannot open: %s\n",C_RED,C_RESET,batch);net_cleanup();return 1;}
        char line[MAX_DOM]; int cnt=0;
        while(fgets(line,sizeof(line),f)){
            s_trim(line); if(!line[0]||line[0]=='#') continue;
            char dom[MAX_DOM]; clean_dom(line,dom,sizeof(dom));
            if(!valid_dom(dom)) continue;
            printf("\n%s[Batch %d]%s %s\n",C_RED,++cnt,C_RESET,dom);
            run_scan(dom,skip_ports);
        }
        fclose(f);
        printf("\n%s%s[✓] Batch done: %d domain(s) scanned%s\n",C_GREEN,C_BOLD,cnt,C_RESET);
        net_cleanup(); return 0;
    }
 
    if(target){
        char dom[MAX_DOM]; clean_dom(target,dom,sizeof(dom));
        if(!valid_dom(dom)){fprintf(stderr,"%s[-]%s Invalid domain\n",C_RED,C_RESET);net_cleanup();return 1;}
        run_scan(dom,skip_ports);
        net_cleanup(); return 0;
    }
 
    /* Interactive */
    printf("  %sWindows:%s gcc -O2 -o domain_osint.exe domain_osint.c -lws2_32 -ldnsapi\n",C_YELLOW,C_RESET);
    printf("  %sLinux:  %s gcc -O2 -o domain_osint domain_osint.c -lresolv -lpthread\n\n",C_YELLOW,C_RESET);
    while(1){
        printf("\n%s══════════════════════════════════════════════════════%s\n",C_RED,C_RESET);
        printf("%s[?]%s Enter domain (or 'exit'): ",C_RED,C_RESET);
        fflush(stdout);
        char inp[MAX_DOM];
        if(!fgets(inp,sizeof(inp),stdin)) break;
        s_trim(inp); if(!inp[0]) continue;
        if(!strcmp(inp,"exit")||!strcmp(inp,"quit")||!strcmp(inp,"q"))
            {printf("%s[!] Exiting...%s\n",C_YELLOW,C_RESET);break;}
        char dom[MAX_DOM]; clean_dom(inp,dom,sizeof(dom));
        if(!valid_dom(dom)){printf("  %s[!]%s Invalid domain. Example: example.com\n",C_YELLOW,C_RESET);continue;}
        run_scan(dom,0);
    }
    net_cleanup(); return 0;
}
 
