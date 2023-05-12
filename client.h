#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "common.h"

#define CERTIFICATEFILE "/home/vagrant/tls/phone2.crt"
#define KEYFILE "/home/vagrant/tls/phone2.key"
#define PASSWORD "password"

int tcp_connect();
void check_cert_chain (SSL *ssl, char *host);

#endif


