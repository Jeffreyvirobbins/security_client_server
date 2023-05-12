#include "common.h"

/**
 *
 */
int echo (SSL *ssl, int sock) {

    char buf[BUFSIZZ];
    int r, len, offset;

    printf ("%lu %d %s %s, sock: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, sock);
    while (1) {

        // First read the data
        r = SSL_read (ssl, buf, BUFSIZZ);

        int ssl_error_value = SSL_get_error (ssl, r);
        switch (ssl_error_value) {

            case SSL_ERROR_NONE:
                len = r;
                break;

            case SSL_ERROR_ZERO_RETURN:
                // End of data
                goto end;
                break;

            default: 
                berr_exit ("SSL read problem");
        }

        // Now keep writing until we write everyting
        r = SSL_write (ssl, buf + offset, len);
        switch (SSL_get_error (ssl, r)) {

            case SSL_ERROR_NONE:
                len -= r;
                offset += r;
                break;

            default: 
                berr_exit ("SSL write problem");
        }

    } // while (1)

end:
    SSL_free (ssl);
    close (sock);
    return 0;
}

