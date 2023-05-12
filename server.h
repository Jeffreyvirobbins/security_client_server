#ifndef _SERVER_H_
#define _SERVER_H_

#include "common.h"

#define CERTIFICATEFILE "/home/vagrant/tls/server.crt"
#define KEYFILE "/home/vagrant/tls/server.key"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"

int tcp_listen();
void load_dh_params (SSL_CTX *ctx, char *file);
void generate_eph_rsa_key (SSL_CTX *ctx);

#endif

