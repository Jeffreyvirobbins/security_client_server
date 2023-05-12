#include "common.h"
#include "client.h"
#include "read_write.h"

int main (int argc, char *argv[]) {

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int sock;

    // Build our SSL context
    ctx = initialize_ctx (KEYFILE, PASSWORD);
    sock = tcp_connect();
    ssl = SSL_new (ctx);

    sbio = BIO_new_socket (sock, BIO_NOCLOSE);
    SSL_set_bio (ssl, sbio, sbio);
    if  (SSL_connect (ssl) <= 0) {
        berr_exit ("SSL conect error");
    }
    check_cert_chain (ssl, HOST);

    printf ("%lu %d %s %s, SSL connect to server with success\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__);

    read_write (ssl, sock);
    destory_ctx (ctx);
}

