#include "common.h"

int tcp_connect() {

    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;

    if (!(hp = gethostbyname (HOST))) {
        berr_exit ("Couldn't resolve host");
    }
    printf ("%lu %d %s %s, Offical name: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, hp->h_name);

    memset (&addr, 0, sizeof (addr));
    addr.sin_addr = *(struct in_addr *) hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons (PORT);

    // prints details of hp
    /*
    while (*hp->h_aliases) {
        printf("%lu %d %s %s, alias: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, *hp->h_aliases ++);
    }

    while (*hp->h_addr_list) {
        struct in_addr a;
        bcopy (*hp->h_addr_list ++, (char *) &a, sizeof(a));
        printf ("%lu %d %s %s, IP address: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, inet_ntoa(a));
        break;
    }
    */
 
    printf ("%lu %d %s %s, port: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, PORT);

    // Big mistake here
    //if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) < 0)) {
    if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err_exit ("Couldn't create socket\n");
    }
        printf ("%lu %d %s %s, sock: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, sock);

    int status = connect (sock, (struct sockaddr *) &addr, sizeof (addr));
    printf ("%lu %d %s %s, status: %d\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, status);

    // if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    if (status < 0) {
        err_exit ("Couldn't connect socket\n");
    }
    printf ("%lu %d %s %s, Connect success to %s:\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, hp->h_name);
    return sock;
}

void check_cert_chain (SSL *ssl, char *host) {

    X509 *peer;
    char peer_CN[256];

    if (SSL_get_verify_result (ssl) != X509_V_OK) {
        berr_exit ("Certificate doesn't verify");
    }

    // Check the common name
    peer = SSL_get_peer_certificate (ssl);
    X509_NAME_get_text_by_NID (
            X509_get_subject_name (peer), 
            NID_commonName, 
            peer_CN,
            256
            );
    if (strcasecmp (peer_CN, host)) {
        berr_exit ("Common name doesn't match host name");
    }

    return;
}

