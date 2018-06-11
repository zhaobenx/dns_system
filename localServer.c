#include "dns.h"


DNSCache *find_in_cache(DNSCache *cache, DNSQuery *dnsQuery)
{
    DNSCache *ptr = cache;
    ptr = ptr->next;// 跳过首部
    while (ptr)
    {
        if (!strcasecmp(dnsQuery->name, ptr->query) && dnsQuery->type == ptr->type && dnsQuery->class == ptr->class_)
        {
            return ptr;
        }
        ptr = ptr->next;
    }
    return NULL;
}


void add_to_cache(struct DNSCache *cache, DNSRr *dnsRr)
{
    // insert to tail
    struct DNSCache *ptr = cache;

    while (ptr->next)
        ptr = ptr->next;
    printf("Adding \"%s\" --> \"%s\" to cache...\n", dnsRr->name, dnsRr->data);
    // build cache
    struct DNSCache *rr = (struct DNSCache *) malloc(sizeof(struct DNSCache));
    rr->query = (char *) malloc(strlen(dnsRr->name) + 1);
    strcpy(rr->query, dnsRr->name);
    rr->ttl = dnsRr->ttl;
    rr->type = dnsRr->type;
    rr->class_ = dnsRr->class;
    rr->result = (char *) malloc(strlen(dnsRr->data) + 1);
    strcpy(rr->result, dnsRr->data);
    rr->next = NULL;

    ptr->next = rr;

}

DNSBody *queryFromServer(int socket_handler, DNSQuery *dnsQuery, char *dns_server)
{
    struct sockaddr_in dns_server_address = {};
    dns_server_address.sin_family = AF_INET;
    dns_server_address.sin_port = htons(DNS_PORT);  // DNS 53
    dns_server_address.sin_addr.s_addr = inet_addr(dns_server);

    srand((unsigned int) time(NULL));
    unsigned short usId = (unsigned short) rand();

    int query_length;


    DNSBody query;
    memset(&query, 0, sizeof(DNSBody));
    memset(&query.dnsHeader, 0, sizeof(DNSHeader));

    query.dnsHeader.QR = 0;
    query.dnsHeader.Questions = 1;
    query.dnsHeader.RD = 1;
    query.query = dnsQuery;

    size_t queryLength;
    char *serResponse = serilizeDNS(query, &queryLength);

    if (sendto(socket_handler,
               serResponse,
               queryLength,
               0,
               (struct sockaddr *) &dns_server_address,
               sizeof(dns_server_address)) < 1
            )
    {
        perror("Send dns package");
    }

    free(serResponse);
//    releaseDNS(query);


    //recv
    char buf[BUF_SIZE];

    int ret;
    socklen_t len = sizeof(dns_server_address);
    if ((ret = recvfrom(socket_handler,
                        buf,
                        BUF_SIZE,
                        0,
                        (struct sockaddr *) &dns_server_address,
                        (socklen_t *) &len)) < 1)
    {
        perror("receive socket");
        return NULL;
    }

    return deserializeDNS(buf, ret);


}

// www.baidu.com -> [com, baidu.com, www.baidu.com]
char **splitUrl(char *url)
{
    int number = 0;
    char *domain = (char *) malloc(strlen(url) + 3);
    char *ptr, *end;
    char **result;
    char **result_ptr;

    *domain = '.';
    strcpy(domain + 1, url);
    ptr = domain;
    while (*ptr)
    {
        if (*ptr == '.')
            number++;
        ptr++;
    }

    end = ptr;

    result = (char **) malloc(sizeof(char *) * (number + 2));
    result_ptr = result;

    ptr = end - 1;
    while (ptr != domain - 1)
    {
        if (*ptr == '.')
        {
            size_t length = end - ptr - 1;
            *result_ptr = (char *) malloc(length + 2);
            memcpy(*result_ptr, ptr + 1, length);
            (*result_ptr)[length] = '\0';
            result_ptr++;
//            end = ptr;
        }
        ptr--;
    }

    *result_ptr = NULL;
    return result;
}

int main(int argc, char **argv)
{

//    for(char** x = splitUrl("www.baudu.com"); *x!= NULL; x++)
//    {
//        printf("%s\n",*x);
//
//    }
//    return 0;

    const char root_server[] = "127.1.1.1";
    unsigned short port = DNS_PORT;
    const char host[] = "127.0.0.1";


    struct sockaddr_in server, client;
    int client_length;
    char buf[BUF_SIZE];

    int query_length;
    struct DNSCache *cache = (struct DNSCache *) malloc(sizeof(struct DNSCache));// cache linked list
    bzero(cache, sizeof(struct DNSCache));


    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(port);

    // initialize tcp server
    int socket_server = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_server < 0)
    {
        perror("Could not create tcp socket");
        return -2;
    }
    if (bind(socket_server, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        perror("Bind failed. Error");
        return -3;
    }
    printf("Local server starts....\n");
    listen(socket_server, 10);


    // initialize udp client
    int udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0)
    {
        perror("Could not create udp socket");
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    // set timeout
    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        perror("Error on setting timeout");
    if (setsockopt(socket_server, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        perror("Error on setting timeout");


    // tcp main loop
    while (1)
    {
        int socket_client = accept(socket_server, (struct sockaddr *) &client, (socklen_t *) &client_length);
        if (socket_client < 0)
        {
            perror("Accept error");
            return -4;
        }
        printf("*******************************************\n");
        clock_t time_s = clock();
        printf("Get new connection\n");


        if ((query_length = recv(socket_client, buf, BUF_SIZE, 0)) < sizeof(struct DNSHeader) + 2)
        {
            printf("Error in receive/unpackage dns\n");
            shutdown(socket_client, SHUT_RDWR);
            close(socket_client);
            continue;
        }

        // tcp 2 bytes header
        DNSBody dnsBody;
        DNSBody *temp = deserializeDNS(buf + 2, query_length - 2);
        if (temp == NULL)
        {
            printf("Error receiving client message.\n");
            continue;
        }
        memcpy(&dnsBody, temp, sizeof(DNSBody));
        free(temp);
        DNSBody query;
        DNSBody response;
        DNSQuery *dnsQuery;
        DNSCache *queryResult;

        memset(&response, 0, sizeof(DNSBody));
        memset(&response.dnsHeader, 0, sizeof(DNSHeader));
        memset(&query, 0, sizeof(DNSBody));
        memset(&query.dnsHeader, 0, sizeof(DNSHeader));


        if (dnsBody.dnsHeader.QR == 0 && dnsBody.dnsHeader.Questions > 0 && (dnsBody.dnsHeader.opcode == 0x0) &&
            (dnsBody.dnsHeader.zero == 0x0))
        {
            response.dnsHeader.QR = 1;

            for (int i = 0; i < dnsBody.dnsHeader.Questions; ++i)
            {
                dnsQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                memcpy(dnsQuery, dnsBody.query + i, sizeof(DNSQuery));
                queryResult = find_in_cache(cache, dnsQuery);
                // find in cache
                if (queryResult)
                {
                    response.dnsHeader.AnswerRRs++;
                    DNSRr *dnsAnswer = (DNSRr *) malloc(sizeof(DNSRr));
                    dnsAnswer->type = queryResult->type;
                    strcpy(dnsAnswer->name, queryResult->query);
                    strcpy(dnsAnswer->data, queryResult->result);
                    dnsAnswer->class = queryResult->class_;
                    dnsAnswer->ttl = queryResult->ttl;
                    response.query = dnsQuery;
                    response.answer = dnsAnswer;

                    printf("Find result in cache for \"%s\" -> \"%s\" type is %d \n", dnsQuery->name, dnsAnswer->data,
                           dnsAnswer->type);

                    if (dnsAnswer->type == T_MX)
                    {
                        DNSQuery *mxQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                        memcpy(mxQuery, dnsQuery, sizeof(DNSQuery));
                        mxQuery->type = T_A;
                        DNSCache *mxAddress = find_in_cache(cache, mxQuery);
                        free(mxQuery);
                        if (mxAddress)
                        {
                            response.dnsHeader.AdditionalRRs++;
                            DNSRr *dnsAdditional = (DNSRr *) malloc(sizeof(DNSRr));
                            dnsAdditional->type = mxAddress->type;
                            strcpy(dnsAdditional->name, mxAddress->query);
                            strcpy(dnsAdditional->data, mxAddress->result);
                            dnsAdditional->class = mxAddress->class_;
                            response.additional = dnsAdditional;
                        }
                    }
                } else // not in cache
                {
                    DNSQuery *ipQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                    memcpy(ipQuery, dnsQuery, sizeof(DNSQuery));
                    ipQuery->type = T_A;
                    DNSCache *ipAddress = find_in_cache(cache, ipQuery);
                    free(ipQuery);
                    char ip[32];
                    // if  ip address in chache
                    if (!ipAddress)
                    {
                        DNSQuery *tempQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                        memcpy(tempQuery, dnsQuery, sizeof(DNSQuery));
                        tempQuery->type = T_A;

                        strcpy(ip, root_server);
                        char **splited = splitUrl(dnsQuery->name);
                        for (char **x = splited; *x != NULL;)
                        {
                            strcpy(tempQuery->name, *x);
                            DNSBody *temp = queryFromServer(udp_socket, tempQuery, ip);
                            if (temp != NULL)
                            {
                                memcpy(&response, temp, sizeof(DNSBody));
                                strcpy(ip, temp->answer->data);
                                add_to_cache(cache, temp->answer);
                                free(temp);
                                printf("Query \"%s\" from %s\n", *x, ip);
                            } else
                            {
                                printf("Cannot find \"%s\" from %s\n", *x, ip);
                                break;
                            }

                            free(*x);
                            x++;
                        }
                        free(tempQuery);
                        free(splited);
                    } else
                    {
                        strcpy(ip, ipAddress->result);
                    }

                    DNSQuery *tempQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                    memcpy(tempQuery, dnsQuery, sizeof(DNSQuery));
                    DNSBody *temp = queryFromServer(udp_socket, tempQuery, ip);
                    free(tempQuery);
                    if (temp != NULL)
                    {
                        memcpy(&response, temp, sizeof(DNSBody));
                        if (temp->answer)
                        {
                            add_to_cache(cache, temp->answer);
//                            printf("Add \"%s\" --> \"%s\" to cache\n", temp->answer->name, temp->answer->data);

                        }
                        if (temp->additional)
                        {
                            add_to_cache(cache, temp->additional);
//                            printf("Add \"%s\" --> \"%s\" to cache\n", temp->additional->name, temp->additional->data);
                        }
                        free(temp);
                    }

                }
            }
            size_t responseLength;
            char *serResponse = serilizeDNS(response, &responseLength);
            char *tcpResponse = (char *) malloc(responseLength + 2);
            *(unsigned short *) tcpResponse = htons(responseLength);
            memcpy(tcpResponse + 2, serResponse, responseLength);
            printf("Send back to client!\n");

            if (send(socket_client, tcpResponse, responseLength + 2, 0) < -1)
            {
                perror("Error in sending to client");
            }

            free(serResponse);
            free(tcpResponse);
            releaseDNS(response);
            releaseDNS(dnsBody);

        }

        printf("Time spent：%.3fs\n", (double) (clock() - time_s) / CLOCKS_PER_SEC);

        printf("=======++++++=======\n");
    }

    return 0;
}