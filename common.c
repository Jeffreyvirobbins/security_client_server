#include "common.h"

BIO *bio_err = 0;
static char *pass;

void sigpipe_handle (int x) {
}

static int password_cb (char *buf, int num, int rwflg, void *userdata) {
    if (num < strlen (pass) + 1) {
        return 0;
    }

    printf ("%lu %d %s %s, password: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, 
           pass 
           );
    strcpy (buf, pass);
    return (strlen (pass));
}

// simple error and exit routine
int err_exit (char *string) {
    fprintf (stderr, "%lu %d %s %s, %s", pthread_self(), __LINE__, __FILE__, __FUNCTION__, string);
    exit (0);
}


// SSL errors and exit
int berr_exit (char *string) {

    BIO_printf (bio_err, "%s\n", string);
    ERR_print_errors (bio_err);
    exit (0);
}


SSL_CTX * initialize_ctx (char *keyfile, char *password) {

    if (!bio_err) {

        // global system initialization
        SSL_library_init();
        SSL_load_error_strings();

        // An error write context
        bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
    }

    // set up a signal handler
    signal (SIGPIPE, sigpipe_handle);

    // Create our context
    const SSL_METHOD *meth = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new (meth);
    if (ctx == NULL) {
        berr_exit ("init SSL CTX failed\n");
    }

    SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth (ctx, 5);

    // Load our key and certificate
    printf ("%lu %d %s %s, password: %s, keyfile: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, 
           pass,
           keyfile
           );
    if (!(SSL_CTX_use_certificate_file (ctx, keyfile, SSL_FILETYPE_PEM))) {
        berr_exit ("Couldn't read certificate file");
    }

    pass = password;
    SSL_CTX_set_default_passwd_cb (ctx, password_cb);
    if (!(SSL_CTX_use_PrivateKey_file (ctx, keyfile, SSL_FILETYPE_PEM))) {
        berr_exit ("Couldn't read key file");
    }

    /*
    // Load the CAs we trust
    if (!(SSL_CTX_load_verify_locations (ctx, CA_LIST, 0))) {
        berr_exit ("Coundn't read CA list");
    }
    SSL_CTX_set_verify_depth (ctx, 1);

    // Load randomness
    if (!(RAND_load_file (RANDOM, 1024 * 1024, -1))) {
        berr_exit ("Coundn't load randomness");
    }
    */

    return ctx;
}

void destory_ctx (SSL_CTX * ctx) {
    SSL_CTX_free (ctx);
    return;
}

