#include <ctype.h>
#include "dns.h"


char *trimwhitespace(char *str)
{
    char *end;

    // Trim leading space
    while (isspace((unsigned char) *str)) str++;

    if (*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}


DNSCache *read_from_file(const char *filename)
{

    char *line;
    size_t len = 0;
    ssize_t read;
    struct DNSCache *result;

    FILE *f = fopen(filename, "r");

    if (f == NULL)
    {
        perror("Can not open dns file");
        return NULL;
    }


    char *found;
    result = (DNSCache *) malloc(sizeof(DNSCache));
    DNSCache *ptr = result;

    while ((read = getline(&line, &len, f)) != -1)
    {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || !strcasecmp(line, " ") || strlen(line) == 0)
            continue;

        ptr->next = (DNSCache *) malloc(sizeof(DNSCache));
        ptr = ptr->next;
        ptr->next = NULL;

        // query
        if ((found = strsep(&line, ",")) != NULL)
        {
            ptr->query = trimwhitespace(found);
        } else
        {
            perror("reading query error!");
            continue;
        }
        // ttl
        if ((found = strsep(&line, ",")) != NULL)
        {
            ptr->ttl = atoi(found);
        } else
        {
            perror("reading  ttl error!");
            continue;

        }
        // class
        if ((found = strsep(&line, ",")) != NULL)
        {

            if (!strcasecmp((trimwhitespace(found)), "IN"))
            {
                ptr->class_ = C_IN;
            } else
            {
                printf("not supported class class %s\n", found);
                continue;
            }
        } else
        {
            perror("reading class error!");
            continue;

        }
        // type
        if ((found = strsep(&line, ",")) != NULL)
        {

            if (!strcasecmp((trimwhitespace(found)), "A"))
                ptr->type = T_A;
            if (!strcasecmp(trimwhitespace(found), "MX"))
                ptr->type = T_MX;
            if (!strcasecmp(trimwhitespace(found), "CNAME"))
                ptr->type = T_CNAME;
        } else
        {
            perror("reading type error!");
            continue;

        }
        // result
        if ((found = strsep(&line, ",")) != NULL)
        {
            char *temp = trimwhitespace(found);
            ptr->result = (char *) malloc(strlen(temp) + 2);
            strcpy(ptr->result, temp);
//			printf("%s\n", record->result);
        } else
        {
            perror("reading result error!");
            continue;

        }

    }

    fclose(f);

    return result;
}

DNSCache *get_result(const DNSCache *database, char *query, int type)
{

    DNSCache *ptr = database->next;

    while (ptr)
    {
        if (!strcasecmp(ptr->query, query))
        {
            if (ptr->type == type)
                return ptr;
        }
        ptr = ptr->next;
    }
    return NULL;

}

int main(int argc, char **argv)
{


    int sockfd;
    unsigned short portno = DNS_PORT;
    char ip[32] = "127.1.1.1";
    char dnsFile[256];
    char buf[BUF_SIZE];
    char *hostaddrp;
    struct hostent *hostp;
    struct sockaddr_in serveraddr, clientaddr;

    if (argc > 1)
    {
        strcpy(ip, argv[1]);
        strcpy(dnsFile, argv[1]);

        printf("Working on %s:%hu\n", ip, portno);
    } else
    {
        printf("Use %s 127.1.1.1 to bind ip and read dns file\n", argv[0]);
        exit(0);
    }

    strcat(dnsFile, "/");
    strcat(dnsFile, "dns.txt");


    int database_length = 0;
    DNSCache *databse = read_from_file(dnsFile);
    if (databse == NULL)
    {
        printf("Error reading dns file %s\n", dnsFile);
        exit(-1);
    }
    DNSCache *ptr = databse->next;
    while (ptr)
    {
        database_length++;
        ptr = ptr->next;
    }
//    DNSCache* result = get_result(databse,"baidu", T_A);
//    if(result)
//        printf("result %s\n", result->result);


    printf("Database length: %d\n", database_length);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(-1);
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *) &optval, sizeof(int));

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(ip);
    serveraddr.sin_port = htons((unsigned short) portno);

    if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
    {
        perror("ERROR on binding");
        exit(-1);
    }
    printf("Server start:\n");
    int clientlen = sizeof(clientaddr);

    while (1)
    {

        bzero(buf, BUF_SIZE);
        int received;
        received = recvfrom(sockfd, buf, BUF_SIZE, 0,
                            (struct sockaddr *) &clientaddr, &clientlen);
        if (received < 0)
        {
            perror("Error in recvfrom");
            continue;

        }
        printf("Start responsing\n");

        if (received < sizeof(DNSHeader))
        {
            printf("Wrong dns query\n");
            continue;
        }

        DNSBody dnsBody = deserializeDNS(buf, received);
        DNSBody response;
        DNSQuery *dnsQuery;
        DNSCache *databaseResult;
        memset(&response, 0, sizeof(DNSBody));
        memset(&response.dnsHeader, 0, sizeof(DNSHeader));


        if (dnsBody.dnsHeader.QR == 0 && dnsBody.dnsHeader.Questions > 0 && (dnsBody.dnsHeader.opcode == 0x0) &&
            (dnsBody.dnsHeader.zero == 0x0))
        {
            response.dnsHeader.QR = 1;

            for (int i = 0; i < dnsBody.dnsHeader.Questions; ++i)
            {
                response.dnsHeader.Questions++;
                dnsQuery = (DNSQuery *) malloc(sizeof(DNSQuery));
                memcpy(dnsQuery, dnsBody.query + i, sizeof(DNSQuery));
                databaseResult = get_result(databse, dnsQuery->name, dnsQuery->type);
                if (databaseResult)
                {
                    response.dnsHeader.AnswerRRs++;
                    DNSRr *dnsAnswer = (DNSRr *) malloc(sizeof(DNSRr));
                    dnsAnswer->type = databaseResult->type;
                    strcpy(dnsAnswer->name, databaseResult->query);
                    strcpy(dnsAnswer->data, databaseResult->result);
                    dnsAnswer->class = databaseResult->class_;
                    dnsAnswer->ttl = databaseResult->ttl;
                    response.query = dnsQuery;
                    response.answer = dnsAnswer;


                    printf("Find result for \"%s\" -> \"%s\" type is %d \n", dnsQuery->name, databaseResult->result,
                           databaseResult->type);

                    if (databaseResult->type == T_MX)
                    {
                        DNSCache *mxAddress = get_result(databse, dnsQuery->name, T_A);
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

                }

            }
        }
        size_t responseLength;
        char *serResponse = serilizeDNS(response, &responseLength);
        if (sendto(sockfd, serResponse, responseLength, 0, (struct sockaddr *) &clientaddr, clientlen) < 0)
            perror("Error in sendto");
        free(serResponse);
        releaseDNS(response);
        releaseDNS(dnsBody);

        printf("=======+++++=======\n");


    }

}



