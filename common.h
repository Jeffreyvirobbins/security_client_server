#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h> // inet_ntoa
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <fcntl.h>
#include <signal.h>

#include <pthread.h>

// located at /usr/local/include/
#include <openssl/err.h>
#include <openssl/ssl.h>

#define CA_LIST "root.pem"

// #define HOST "localhost"

// Staging1 pnn root
#define HOST "ec2-13-57-78-244.us-west-1.compute.amazonaws.com"


// Production pnn root
// #define HOST "ec2-54-241-160-4.us-west-1.compute.amazonaws.com"

#define PORT 443

#define RANDOM "random.pem"
#define BUFSIZZ 1024

extern BIO *bio_err;
int berr_exit (char *string);
int err_exit (char *string);


SSL_CTX *initialize_ctx (char *keyfile, char *password);
void destory_ctx (SSL_CTX *ctx);

#endif


