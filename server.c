#include "common.h"
#include "server.h"

#define KEY_LENGTH 768
#define PUB_EXP 65537

int tcp_listen() {

    int sock;
    struct sockaddr_in sin;
    int val = 1;

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
        err_exit ("Couldn't create socket\n");
    }
    printf ("%lu %d %s %s, sock: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, sock);

    memset (&sin, 0, sizeof (sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons (PORT);
    setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val));
    printf ("%lu %d %s %s, sock: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, sock);

    if (bind (sock, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
        err_exit ("Couldn't bind socket\n");
    }

    listen (sock, 5);
    return sock;
}

void load_dh_params (SSL_CTX *ctx, char *file) {

    DH *ret = 0;
    BIO *bio;
    if ((bio = BIO_new_file (file, "r")) == NULL) {
        err_exit ("Couldn't open DH file\n");
    }

    ret = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);

    BIO_free (bio);
    if (SSL_CTX_set_tmp_dh (ctx, ret) < 0 ) {
        err_exit ("Couldn't set DH parameters\n");
    }

    return;
}

void generate_eph_rsa_key (SSL_CTX *ctx) {

    BIGNUM *bne = NULL;
    RSA *rsa;
    int ret;

    // Generate key pair
    printf ("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush (stdout);

    bne = BN_new();
    ret = BN_set_word (bne, PUB_EXP);
    if (ret != 1) {
        err_exit ("Couldn't BN_set_word\n");
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex (rsa, KEY_LENGTH, bne, NULL);

    if (!SSL_CTX_set_tmp_rsa (ctx, rsa)) {
        err_exit ("Couldn't set RSA key\n");
    }

    RSA_free (rsa);
    return;
}

