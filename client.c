#include "dns.h"


int queryDNS(int socket_handler, char *domain_name, unsigned short type)
{

    char buf[BUF_SIZE];
    // package dns body
    DNSBody dnsBody;
    memset(&dnsBody, 0, sizeof(DNSBody));
    memset(&dnsBody.dnsHeader, 0, sizeof(DNSHeader));

    dnsBody.dnsHeader.QR = 0;
    dnsBody.dnsHeader.RD = 1;
    dnsBody.dnsHeader.Questions = 1;

    DNSQuery *dnsQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
    dnsQuery->type = type;
    dnsQuery->class = C_IN;
    strcpy(dnsQuery->name, domain_name);

    dnsBody.query = dnsQuery;

    size_t bodyLength;
    char *serBory = serilizeDNS(dnsBody, &bodyLength);
    // add length before the packet
    char *tcpBody = (char *) malloc(bodyLength + 2);
    *(unsigned short *) tcpBody = htons(bodyLength);
    memcpy(tcpBody + 2, serBory, bodyLength);
    printf("Send back to client!\n");

    if (send(socket_handler, tcpBody, bodyLength + 2, 0) < -1)
    {
        perror("Error in sending to client");
        return -1;
    }
    free(serBory);
    free(tcpBody);

    releaseDNS(dnsBody);


    int received = recv(socket_handler, buf, BUF_SIZE, 0);
    if (received < sizeof(struct DNSHeader) + 2)
    {
        printf("Error in receive/unpackage dns\n");
        shutdown(socket_handler, SHUT_RDWR);
        close(socket_handler);
        return -2;
    }


    // tcp 2 bytes header

    DNSBody *response = deserializeDNS(buf + 2, received - 2);
    if (response == NULL)
    {
        printf("Error receiving client message.\n");
        return -4;
    }

    for(int i = 0;i<response->dnsHeader.AnswerRRs;++i){
        DNSRr * answer = response->answer+i;
        if(answer->type == T_A)
            printf("Get ip %s for \"%s\", ttl is %d\n",answer->data, answer->name,answer->ttl);
        if(answer->type == T_MX)
            printf("Get mail exchange \"%s\" for \"%s\", ttl is %d\n",answer->data, answer->name, answer->ttl);
        if(answer->type == T_CNAME)
            printf("Get cname \"%s\" for \"%s\", ttl is %d\n",answer->data, answer->name, answer->ttl);
    }
    for(int i = 0;i<response->dnsHeader.AdditionalRRs;++i){
        DNSRr * additional = response->additional+i;
        if(additional->type == T_A)
            printf("Get additional ip %s for \"%s\", ttl is %d\n",additional->data, additional->name,additional->ttl);
        if(additional->type == T_MX)
            printf("Get additional mail exchange \"%s\" for \"%s\", ttl is %d\n",additional->data, additional->name, additional->ttl);
        if(additional->type == T_CNAME)
            printf("Get additional cname \"%s\" for \"%s\", ttl is %d\n",additional->data, additional->name, additional->ttl);
    }


    free(response);
    return 0;

}

void print_help(char *name)
{
    printf("Usage:\n     %s [-A|-MX|-CNAME] url\n-----\n     Default type is A\n", name);
    exit(0);
}

int main(int argc, char **argv)
{

    unsigned short type;
    char *query_name;

    if (argc < 2 || argc > 3)
    {
        print_help(argv[0]);
    } else
    {
        if (argc == 2)
        {
            type = T_A;
            query_name = argv[1];
        } else
        {
            if (!strcasecmp(argv[1], "-A"))
            {
                type = T_A;
            } else if (!strcasecmp(argv[1], "-MX"))
            {
                type = T_MX;
            } else if (!strcasecmp(argv[1], "-CNAME"))
            {
                type = T_CNAME;
            } else
            {
                printf("Unknown argument: %s\n", argv[1]);
                print_help(argv[0]);
            }
            query_name = argv[2];
        }

    }


    const char local_server[] = "127.0.0.1";
    const unsigned short port = DNS_PORT;


    struct sockaddr_in server, client;
    int client_length;
    char buf[BUF_SIZE];

    int query_length;


    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(local_server);
    server.sin_port = htons(port);


    // initialize tcp client
    int socket_client = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_client < 0)
    {
        perror("Could not create tcp socket");
        return -2;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;


    if (setsockopt(socket_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        perror("Error on setting timeout");
    if (setsockopt(socket_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        perror("Error on setting timeout");

    if (connect(socket_client, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        perror("Error in connecting to local server");
        return -1;
    }

    if (queryDNS(socket_client, query_name, type))
    {
        printf("Error happens\n");
    }


    close(socket_client);

    return 0;

}