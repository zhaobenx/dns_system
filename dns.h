#ifndef DNS_PJ_DNS_H
#define DNS_PJ_DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>


#pragma pack(push, 1)
typedef struct DNSHeader
{
    unsigned short usTransID;

    unsigned char RD : 1;
    unsigned char TC : 1;
    unsigned char AA : 1;
    unsigned char opcode : 4;
    unsigned char QR : 1;

    unsigned char rcode : 4;
    unsigned char zero : 3;
    unsigned char RA : 1;

    unsigned short Questions;
    unsigned short AnswerRRs;
    unsigned short AuthorityRRs;
    unsigned short AdditionalRRs;
} DNSHeader;
#pragma pack(pop)


typedef struct DNSQuery
{
    char name[256];
    unsigned short type;
    unsigned short class;

} DNSQuery;

typedef struct DNSRr
{
    char name[256];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short dataLength;
    char data[256];


} DNSRr;

typedef struct DNSBody
{
    DNSHeader dnsHeader;
    DNSQuery *query;
    DNSRr *answer;
    DNSRr *authority;
    DNSRr *additional;
} DNSBody;

typedef struct List
{
    char *content;
    size_t length;
    struct List *next;
} List;


#define T_A 1 // ipv4
#define T_NS 2 // 域名服务器
#define T_CNAME 5 // 规范名称
#define T_SOA 6 // 开始授权
#define T_PTR 12 // ip转域名
#define T_MX 15 // 邮件服务器

#define C_IN 1;

#define DNS_PORT 5333
#define BUF_SIZE 1024

typedef struct DNSCache
{
    char *query;
    unsigned int ttl;
    unsigned short type;//in
    unsigned short class_; // A, MX, CNAME
    char *result;
    struct DNSCache *next;
} DNSCache;

void checkMalloc(void *ptr);

char *serilizeQuery(DNSQuery *dnsQuery, int *length);

char *serilizeRr(DNSRr *dnsRr, int *length);

char *serilizeDNS(DNSBody dnsBody, size_t *packetLength);

DNSBody deserializeDNS(char *data, size_t length);

void releaseDNS(DNSBody dnsBody);

// www.baidu.com to 03www05baidu03com
char *toInternetFormat(char *name);


//  03www05baidu03com to www.baidu.com
char *toLocalFormat(char *name);


#endif //DNS_PJ_DNS_H
