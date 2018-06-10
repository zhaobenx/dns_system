#include "dns.h"

//int htonl(int a){
//    return a;
//}
//
//unsigned short htons(unsigned short a){
//    return a;
//}

char *toInternetFormat(char *name)
{
    char *result = (char *) malloc(strlen(name) + 2);
    char *domain = (char *) malloc(strlen(name) + 1);
    checkMalloc(result);
    checkMalloc(domain);

    strcpy(domain, name);
    char *dns = result;
    int lock = 0;

    // 尾部补 “.”
    if (domain[strlen((char *) domain) - 1] != '.')
        strcat((char *) domain, ".");

    for (int i = 0; i < strlen((char *) domain); i++)
    {
        if (domain[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = domain[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';

    free(domain);

    return result;
}

char *toLocalFormat(char *name)
{

    char *result = (char *) malloc(256);
    checkMalloc(result);
    char *ptr = result;
    while (*name)
    {
        int p = *name++;
        for (int j = 0; j < (int) p; ++j)
        {

            *ptr++ = *name++;
        }
        *ptr++ = '.';
    }
    *--ptr = '\0';
    return result;
}

char *serilizeDNS(DNSBody dnsBody, size_t *packetLength)
{
    *packetLength = sizeof(DNSHeader);
    int query_number, answer_number, additional_number;
    query_number = dnsBody.dnsHeader.Questions;
    answer_number = dnsBody.dnsHeader.AnswerRRs;
    additional_number = dnsBody.dnsHeader.AdditionalRRs;
    List list, *list_ptr;
    list.next = NULL;
    list_ptr = &list;
    int length;

    for (int i = 0; i < query_number; ++i)
    {
        list_ptr->next = (List *) malloc(sizeof(List));
        list_ptr = list_ptr->next;
        list_ptr->content = serilizeQuery(dnsBody.query + i, &length);
        list_ptr->length = length;
        list_ptr->next = NULL;
        *packetLength += length;
    }
    for (int i = 0; i < answer_number; ++i)
    {
        list_ptr->next = (List *) malloc(sizeof(List));
        list_ptr = list_ptr->next;
        list_ptr->content = serilizeRr(dnsBody.answer + i, &length);
        list_ptr->length = length;

        list_ptr->next = NULL;
        *packetLength += length;
    }
    for (int i = 0; i < additional_number; ++i)
    {
        list_ptr->next = (List *) malloc(sizeof(List));
        list_ptr = list_ptr->next;
        list_ptr->content = serilizeRr(dnsBody.additional + i, &length);
        list_ptr->length = length;

        list_ptr->next = NULL;
        *packetLength += length;
    }

    char *result = (char *) malloc(*packetLength + 10);
    checkMalloc(result);

    dnsBody.dnsHeader.Questions = htons(dnsBody.dnsHeader.Questions);
    dnsBody.dnsHeader.AnswerRRs = htons(dnsBody.dnsHeader.AnswerRRs);
    dnsBody.dnsHeader.AdditionalRRs = htons(dnsBody.dnsHeader.AdditionalRRs);
    dnsBody.dnsHeader.usTransID = htons(dnsBody.dnsHeader.usTransID);


    char *ptr = result;
    memcpy(ptr, &dnsBody.dnsHeader, sizeof(DNSHeader));
    ptr += sizeof(DNSHeader);

    list_ptr = list.next;
    while (list_ptr)
    {
        memcpy(ptr, list_ptr->content, list_ptr->length);
        ptr += list_ptr->length;
        free(list_ptr->content);
        List *del = list_ptr;
        list_ptr = list_ptr->next;
        free(del);
    }
    *packetLength = ptr - result;


    return result;
}

void checkMalloc(void *ptr)
{
    if (ptr == NULL)
    {
        perror("Error in malloc ");
        exit(-1);
    }
}

char *serilizeQuery(DNSQuery *dnsQuery, int *length)
{

    char *formatedName = toInternetFormat(dnsQuery->name);
    char *result = (char *) malloc(strlen(formatedName) + 4 + 2);
    checkMalloc(result);
    char *ptr = result;
    strcpy(ptr, formatedName);

    ptr += strlen(formatedName) + 1;
//    *ptr = '\0';
//    ptr++;
    free(formatedName);
    *(unsigned short *) ptr = htons(dnsQuery->type);
    ptr += 2;
    *(unsigned short *) ptr = htons(dnsQuery->class);
    ptr += 2;
    *length = ptr - result;


    return result;
}

DNSQuery *deserilizeQuery(char *dnsQuery, int *length)
{

    char *name = toLocalFormat(dnsQuery);
    DNSQuery *result = (DNSQuery *) malloc(sizeof(DNSQuery));
    checkMalloc(result);
    char *ptr = (char *) dnsQuery;
    strcpy(result->name, name);
    ptr += strlen(dnsQuery);
    free(name);

    ptr++;
    result->type = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    result->class = ntohs(*(unsigned short *) ptr);
    ptr += 2;

//    *length = ptr - (char *) result +1;
    return result;
}

char *serilizeRr(DNSRr *dnsRr, int *length)
{

    char *formatedName = toInternetFormat(dnsRr->name);
    int dataLength = 0;
    char *formatedData;
    if (dnsRr->type == T_A)
    {
        dataLength = 4;
    } else
    {
        formatedData = toInternetFormat(dnsRr->data);
        dataLength = strlen(formatedData);
    }
    char *result = (char *) malloc(strlen(formatedName) + dataLength + 4 + 4 + 2 + 2 + 2);
    checkMalloc(result);

    char *ptr = result;
    strcpy(ptr, formatedName);

    ptr += strlen(formatedName) + 1;
    free(formatedName);
    *(unsigned short *) ptr = htons(dnsRr->type);
    ptr += 2;
    *(unsigned short *) ptr = htons(dnsRr->class);
    ptr += 2;
    *(unsigned int *) ptr = htonl(dnsRr->ttl);

    ptr += 4;


    if (dnsRr->type == T_MX)
    {
        *(unsigned short *) ptr = htons(dataLength + 3);
        ptr += 2;
        *(unsigned short *) ptr = htons(0x05);
        ptr += 2;
    } else if (dnsRr->type == T_A)
    {
        *(unsigned short *) ptr = htons(dataLength);
        ptr += 2;
    } else
    {
        *(unsigned short *) ptr = htons(dataLength + 1);
        ptr += 2;
    }

    if (dnsRr->type == T_A)
    {
        *(unsigned int *) ptr = inet_addr(dnsRr->data);

    } else
    {
        memcpy(ptr, formatedData, dataLength + 1);
        free(formatedData);
    }
    ptr += dataLength + 1;

    *length = ptr - result;
    return result;
}

DNSRr *deserilizeRr(char *dnsQuery, int *length)
{

    char *name = toLocalFormat(dnsQuery);
    DNSRr *result = (DNSRr *) malloc(sizeof(DNSQuery) + 2);
    checkMalloc(result);
    char *ptr = dnsQuery;
    strcpy(result->name, name);
    ptr += strlen(dnsQuery);

    free(name);

    ptr++;
    result->type = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    result->class = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    result->ttl = ntohl(*(unsigned int *) ptr);
    ptr += 4;
    result->dataLength = ntohs(*(unsigned short *) ptr);
    ptr += 2;
    char *data;
    if (result->type == T_A)
    {
        unsigned int ip = *(unsigned int *) ptr;
        struct in_addr in = {};
        in.s_addr = ip;
//        printf("IP: %s\n", inet_ntoa(in));
        data = inet_ntoa(in);
    } else
    {

        data = toLocalFormat(ptr);
        ptr += strlen(ptr);
    }

//    *length = ptr - (char *) result + 1;
    return result;
}

DNSBody deserializeDNS(char *data, size_t packetlength)
{
//    if (packetlength < sizeof(DNSHeader))
//        return NULL;
    DNSBody result;
    memset(&result, 0, sizeof(DNSBody));
    memcpy(&result.dnsHeader, data, sizeof(DNSHeader));
    char *ptr = data;
    ptr += sizeof(DNSHeader);


    int questions = result.dnsHeader.Questions = ntohs(result.dnsHeader.Questions);
    int answers = result.dnsHeader.AnswerRRs = ntohs(result.dnsHeader.AnswerRRs);
    int additionals = result.dnsHeader.AdditionalRRs = ntohs(result.dnsHeader.AdditionalRRs);
    result.dnsHeader.usTransID = ntohs(result.dnsHeader.usTransID);

    int length;

    if (questions)
    {
        DNSQuery *dnsQuery = (DNSQuery *) malloc(sizeof(DNSQuery) * questions);
        for (int i = 0; i < questions; ++i)
        {
            DNSQuery *temp = deserilizeQuery(ptr, &length);
            memcpy(dnsQuery + i, temp, sizeof(DNSQuery));
            ptr += length;
            free(temp);
        }
        result.query = dnsQuery;
    }

    if (answers)
    {
        DNSRr *dnsRr = (DNSRr *) malloc(sizeof(DNSRr) * questions);
        for (int i = 0; i < questions; ++i)
        {
            DNSRr *temp = deserilizeRr(ptr, &length);
            memcpy(dnsRr + i, temp, sizeof(DNSRr));
            ptr += length;
            free(temp);
        }
        result.answer = dnsRr;
    }
    if (additionals)
    {
        DNSRr *dnsRr = (DNSRr *) malloc(sizeof(DNSRr) * questions);
        for (int i = 0; i < questions; ++i)
        {
            DNSRr *temp = deserilizeRr(ptr, &length);
            memcpy(dnsRr + i, temp, sizeof(DNSRr));
            ptr += length;
            free(temp);
        }
        result.additional = dnsRr;
    }

    return result;
}

void releaseDNS(DNSBody dnsBody)
{
    if (dnsBody.query)
        free(dnsBody.query);
    if (dnsBody.additional)
        free(dnsBody.additional);
    if (dnsBody.answer)
        free(dnsBody.answer);
    if (dnsBody.authority)
        free(dnsBody.authority);


}
