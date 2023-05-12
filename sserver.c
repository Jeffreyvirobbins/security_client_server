#include "common.h"
#include "server.h"
#include "echo.h"

static int s_server_session_id_context = 1;

int main (int argc, char *argv[]) {

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int sock, s, r;

    // Build our SSL context
    // common for both client and server
    ctx = initialize_ctx (KEYFILE, PASSWORD);

    // server specific initialization
    load_dh_params (ctx, DHFILE);
    generate_eph_rsa_key (ctx);

    SSL_CTX_set_session_id_context (ctx, (void *)&s_server_session_id_context, sizeof s_server_session_id_context);

    sock = tcp_listen();

    while (1) {

        if ((s = accept (sock, 0, 0)) < 0) {
            err_exit ("Problem accepting");
        }

        sbio = BIO_new_socket (sock, BIO_NOCLOSE);
        ssl = SSL_new (ctx);
        SSL_set_bio (ssl, sbio, sbio);
        if ((s = SSL_accept (ssl)) < 0) {
            berr_exit ("SSL accept error");
        }

        echo (ssl, s);
    }

    destory_ctx (ctx);
    exit (0);
}

