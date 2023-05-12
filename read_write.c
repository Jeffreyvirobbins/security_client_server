#include "common.h"

/**
 * read from keyboard, write to the server
 * read from server, write to the screen
 * we use select() to multiplex
 */
int read_write (SSL *ssl, int sock) {

    int width;
    int r, c2sl = 0, c2s_offset = 0;
    fd_set readfds, writefds;
    int shutdown_wait = 0;
    char c2s[BUFSIZZ], s2c[BUFSIZZ];

    // First make socket nonblocking
    int ofcmode = fcntl (sock, F_GETFL, 0);
    ofcmode |= O_NDELAY;
    if (fcntl (sock, F_SETFL, ofcmode)) {
        err_exit ("Cound't make socket nonblocking");
    }

    printf ("%lu %d %s %s, sock: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, sock);
    width = sock + 1;
    while (1) {

        FD_ZERO (&readfds);
        FD_ZERO (&writefds);
        FD_SET (sock, &readfds);

        // If we've still get data to write, then don't try to read
        if (c2sl) {
            FD_SET (sock, &writefds);
        }
        else {
            FD_SET (fileno (stdin), &readfds);
        }

        r = select (width, &readfds, &writefds, 0, 0);
        if (r == 0) {
            continue;
        }

        // Now check if there's data to read
        if (FD_ISSET (sock, &readfds)) {
            do {
                r = SSL_read (ssl, s2c, BUFSIZZ);
                int ssl_error_value = SSL_get_error (ssl, r);

                switch (ssl_error_value) {

                    case SSL_ERROR_NONE:
                        fwrite (s2c, 1, r, stdout);
                        break;

                    case SSL_ERROR_ZERO_RETURN:
                        // End of data
                        if (!shutdown_wait) {
                            SSL_shutdown (ssl);
                        }
                        goto end;

                        break;

                    case SSL_ERROR_WANT_READ:
                        // Do nothing here
                        break;

                    default: 
                        berr_exit ("SSL read problem");
                }

            } while (SSL_pending (ssl));
        }

        // Check for input on the sonsole
        printf ("%lu %d %s %s, Check for input on the sonsole\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__);
        if (FD_ISSET (fileno (stdin), &readfds)) {
            c2sl = read (fileno(stdin), c2s, BUFSIZZ);
            if (c2sl == 0) {
                shutdown_wait = 1;
                if (SSL_shutdown (ssl)) {
                    return 1;
                }
                c2s_offset = 0;
            }
        }
        // end of read part

        // If we've got data to write then try to write it
        if (c2sl && FD_ISSET (sock, &writefds)) {
            r = SSL_write (ssl, c2s + c2s_offset, c2sl);

            switch (SSL_get_error (ssl, r)) {

                case SSL_ERROR_NONE:
                    c2sl -= r;
                    c2s_offset += r;
                    break;

                    // We should have blocked
                case SSL_ERROR_WANT_WRITE:
                    break;

                    // Some other eror
                default: 
                    berr_exit ("SSL write problem");
            }
        }

    } // while (1)

end:
    SSL_free (ssl);
    close (sock);
    return 0;
}

