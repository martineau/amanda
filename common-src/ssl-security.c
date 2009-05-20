/*
 * Amanda, The Advanced Maryland Automatic Network Disk Archiver
 * Copyright (c) 1999 University of Maryland
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of U.M. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  U.M. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * U.M. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL U.M.
 * BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Authors: the Amanda Development Team.  Its members are listed in a
 * file named AUTHORS, in the root directory of this distribution.
 */

/*
 * $Id$
 *
 * ssl-security.c - security and transport over ssl or a ssl-like command.
 *
 * XXX still need to check for initial keyword on connect so we can skip
 * over shell garbage and other stuff that ssl might want to spew out.
 */

#include "amanda.h"
#include "util.h"
#include "event.h"
#include "packet.h"
#include "security.h"
#include "security-util.h"
#include "sockaddr-util.h"
#include "stream.h"
#include "version.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * Number of seconds ssl has to start up
 */
#define	CONNECT_TIMEOUT	20

/*
 * Interface functions
 */
static void ssl_accept(const struct security_driver *,
    char *(*)(char *, void *),
    int, int,
    void (*)(security_handle_t *, pkt_t *),
    void *);
static void ssl_connect(const char *,
    char *(*)(char *, void *),
    void (*)(void *, security_handle_t *, security_status_t), void *, void *);
static ssize_t ssl_data_write(void *c, struct iovec *iov, int iovcnt);
static ssize_t ssl_data_read(void *c, void *bug, ssize_t size);

/*
 * This is our interface to the outside world.
 */
const security_driver_t ssl_security_driver = {
    "SSL",
    ssl_connect,
    ssl_accept,
    sec_close,
    stream_sendpkt,
    stream_recvpkt,
    stream_recvpkt_cancel,
    tcpma_stream_server,
    tcpma_stream_accept,
    tcpma_stream_client,
    tcpma_stream_close,
    sec_stream_auth,
    sec_stream_id,
    tcpm_stream_write,
    tcpm_stream_read,
    tcpm_stream_read_sync,
    tcpm_stream_read_cancel,
    tcpm_close_connection,
    NULL,
    NULL,
    ssl_data_write,
    ssl_data_read
};

static int newhandle = 1;

/*
 * Local functions
 */
static int runssl(struct sec_handle *, in_port_t port,
                  char *ssl_fingerprint_file, char *ssl_cert_file,
                  char *ssl_key_file, char *ssl_ca_cert_file);


/*
 * ssl version of a security handle allocator.  Logically sets
 * up a network "connection".
 */
static void
ssl_connect(
    const char *hostname,
    char *	(*conf_fn)(char *, void *),
    void	(*fn)(void *, security_handle_t *, security_status_t),
    void *	arg,
    void *	datap)
{
    struct sec_handle *rh;
    int result;
    char *canonname;
    char *service;
    in_port_t port;
    char *ssl_fingerprint_file = NULL;
    char *ssl_cert_file = NULL;
    char *ssl_key_file = NULL;
    char *ssl_ca_cert_file = NULL;

    assert(fn != NULL);
    assert(hostname != NULL);

    auth_debug(1, _("ssl: ssl_connect: %s\n"), hostname);

    rh = alloc(sizeof(*rh));
    security_handleinit(&rh->sech, &ssl_security_driver);
    rh->hostname = NULL;
    rh->rs = NULL;
    rh->ev_timeout = NULL;
    rh->rc = NULL;

    result = resolve_hostname(hostname, 0, NULL, &canonname);
    if(result != 0) {
	dbprintf(_("resolve_hostname(%s): %s\n"), hostname, gai_strerror(result));
	security_seterror(&rh->sech, _("resolve_hostname(%s): %s\n"), hostname,
			  gai_strerror(result));
	(*fn)(arg, &rh->sech, S_ERROR);
	return;
    }
    if (canonname == NULL) {
	dbprintf(_("resolve_hostname(%s) did not return a canonical name\n"), hostname);
	security_seterror(&rh->sech,
	        _("resolve_hostname(%s) did not return a canonical name\n"), hostname);
	(*fn)(arg, &rh->sech, S_ERROR);
       return;
    }

    rh->hostname = canonname;	/* will be replaced */
    canonname = NULL; /* steal reference */
    rh->rs = tcpma_stream_client(rh, newhandle++);
    rh->rc->recv_security_ok = &bsd_recv_security_ok;
    rh->rc->prefix_packet = &bsd_prefix_packet;

    if (rh->rs == NULL)
	goto error;

    amfree(rh->hostname);
    rh->hostname = stralloc(rh->rs->rc->hostname);

    if (conf_fn) {
	service = conf_fn("client_port", datap);
	if (strlen(service) <= 1)
	    service = "amanda";
	ssl_fingerprint_file = conf_fn("ssl_fingerprint_file", datap);
	ssl_cert_file        = conf_fn("ssl_cert_file", datap);
	ssl_key_file         = conf_fn("ssl_key_file", datap);
	ssl_ca_cert_file     = conf_fn("ssl_ca_cert_file", datap);
    } else {
	service = "amanda";
    }
    port = find_port_for_service(service, "tcp");
    if (port == 0) {
	security_seterror(&rh->sech, _("%s/tcp unknown protocol"), service);
	goto error;
    }

    /*
     * We need to open a new connection.
     *
     * XXX need to eventually limit number of outgoing connections here.
     */
    if(rh->rc->read == -1) {
	if (runssl(rh, port, ssl_fingerprint_file, ssl_cert_file, ssl_key_file, ssl_ca_cert_file) < 0)
	    goto error;
	rh->rc->refcnt++;
    }

    /*
     * The socket will be opened async so hosts that are down won't
     * block everything.  We need to register a write event
     * so we will know when the socket comes alive.
     *
     * Overload rh->rs->ev_read to provide a write event handle.
     * We also register a timeout.
     */
    rh->fn.connect = fn;
    rh->arg = arg;
    rh->rs->ev_read = event_register((event_id_t)(rh->rs->rc->write),
	EV_WRITEFD, sec_connect_callback, rh);
    rh->ev_timeout = event_register(CONNECT_TIMEOUT, EV_TIME,
	sec_connect_timeout, rh);

    return;

error:
    (*fn)(arg, &rh->sech, S_ERROR);
}

char *validate_fingerprint(X509 *cert, char *fingerprint);
char *validate_fingerprints(X509 *cert, char *ssl_fingerprint_file);

char *validate_fingerprint(
    X509 *cert,
    char *fingerprint)
{
    unsigned char  md[EVP_MAX_MD_SIZE + 1];
    unsigned int   len_md;
    const EVP_MD  *evp_md;
    char *new_fingerprint;
    char *fp;
    unsigned int   i;

    evp_md = EVP_get_digestbyname("MD5");
    if (!evp_md) {
	return g_strdup(_("EVP_get_digestbyname failed"));
    }
    if (!X509_digest(cert, evp_md, md, &len_md)) {
	return g_strdup(_("cannot get MD5 digest"));
    }

    new_fingerprint  = malloc(len_md*3 + 1);
    fp = new_fingerprint;
    for (i=0; i < len_md; i++) {
	snprintf(fp, 4, "%02X:", (unsigned) md[i]);
	fp+=3;
    }
    /* remove latest ':' */
    fp --;
    *fp = '\0';

    if (strcasecmp(new_fingerprint, fingerprint)!= 0) {
	return g_strdup_printf("fingerprint differ %s %s", new_fingerprint, fingerprint);
    }
    amfree(new_fingerprint);
    return NULL;
}

char *validate_fingerprints(
    X509 *cert,
    char *ssl_fingerprint_file)
{
    FILE *fingers;
    char fingerprint[32768];
    char *errmsg = NULL;

    if (ssl_fingerprint_file == NULL || *ssl_fingerprint_file == '\0') {
dbprintf("No fingerprint_file set\n");
	return NULL;
    }

    fingers = fopen(ssl_fingerprint_file, "r");
    if (!fingers) {
	errmsg = g_strdup_printf("Failed open of %s: %s",
				 ssl_fingerprint_file, strerror(errno));
dbprintf("%s\n", errmsg);
	return errmsg;
    }
    while (fgets(fingerprint, 32768, fingers) != NULL) {
	int len = strlen(fingerprint)-1;
	if (len > 0 && fingerprint[len] == '\n')
	    fingerprint[len] = '\0';
	amfree(errmsg);
	errmsg = validate_fingerprint(cert, fingerprint);
	if (errmsg == NULL) {
dbprintf("Fingerprint '%s' match\n", fingerprint);
	    return NULL;
	}
dbprintf("Fingerprint '%s' doesn't match: %s\n", fingerprint, errmsg);
    }
    return errmsg;
}

/*
 * Setup to handle new incoming connections
 */
static void
ssl_accept(
    const struct security_driver *driver,
    char *	(*conf_fn)(char *, void *),
    int		in,
    int		out,
    void	(*fn)(security_handle_t *, pkt_t *),
    void       *datap)
{
    sockaddr_union sin;
    socklen_t_equiv len;
    struct tcp_conn *rc;
    char hostname[NI_MAXHOST];
    int result;
    char *errmsg = NULL;
    int   err;
    X509 *client_cert;
    char *ssl_fingerprint_file = conf_fn("ssl_fingerprint_file", datap);
    char *ssl_cert_file        = conf_fn("ssl_cert_file", datap);
    char *ssl_key_file         = conf_fn("ssl_key_file", datap);
    char *ssl_ca_cert_file     = conf_fn("ssl_ca_cert_file", datap);

dbprintf("ssl_accept\n");
    len = sizeof(sin);
    if (getpeername(in, (struct sockaddr *)&sin, &len) < 0) {
	dbprintf(_("getpeername returned: %s\n"), strerror(errno));
	return;
    }
    if ((result = getnameinfo((struct sockaddr *)&sin, len,
			      hostname, NI_MAXHOST, NULL, 0, 0) != 0)) {
	dbprintf(_("getnameinfo failed: %s\n"),
		  gai_strerror(result));
	return;
    }
    if (check_name_give_sockaddr(hostname,
				 (struct sockaddr *)&sin, &errmsg) < 0) {
	amfree(errmsg);
	return;
    }

    rc = sec_tcp_conn_get(hostname, 0);
    rc->recv_security_ok = &bsd_recv_security_ok;
    rc->prefix_packet = &bsd_prefix_packet;
    copy_sockaddr(&rc->peer, &sin);
    rc->read = in;
    rc->write = out;
    rc->accept_fn = fn;
    rc->driver = driver;
    rc->conf_fn = conf_fn;
    rc->datap = datap;

    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();

    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();

    /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
    rc->meth = SSLv3_method();

    /* Create a SSL_CTX structure */
    rc->ctx = SSL_CTX_new(rc->meth);
    if (!rc->ctx) {
	dbprintf(_("SSL_CTX_new failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	return;
    }
    SSL_CTX_set_mode(rc->ctx, SSL_MODE_AUTO_RETRY);

dbprintf("ssl_accept 3\n");
    if (ssl_cert_file && *ssl_cert_file != '\0') {
dbprintf("load cert file\n");
        /* Load the server certificate into the SSL_CTX structure */
        if (SSL_CTX_use_certificate_file(rc->ctx, ssl_cert_file,
				         SSL_FILETYPE_PEM) <= 0) {
	dbprintf(_("Load ssl-cert-file failed:%s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	    return;
        }
    } else {
	dbprintf("No ssl-cert-file set\n");
	return;
    }

dbprintf("ssl_accept 4\n");
    if (ssl_key_file && *ssl_key_file != '\0') {
dbprintf("load key file\n");
        /* Load the private-key corresponding to the server certificate */
        if (SSL_CTX_use_PrivateKey_file(rc->ctx, ssl_key_file,
				        SSL_FILETYPE_PEM) <= 0) {
	dbprintf(_("Load ssl-key-file failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	    return;
        }
    } else {
	dbprintf(_("No ssl-key-file set\n"));
	return;
    }

dbprintf("ssl_accept 5\n");
    if (ssl_ca_cert_file && *ssl_ca_cert_file != '\0') {
dbprintf("load ca cert file\n");
        /* Load the RSA CA certificate into the SSL_CTX structure */
        if (!SSL_CTX_load_verify_locations(rc->ctx, ssl_ca_cert_file, NULL)) {
	    dbprintf(_("Load ssl-ca-cert-file failed: %s\n"),
		     ERR_error_string(ERR_get_error(), NULL));
	    return;
        }
    } else if (!ssl_fingerprint_file || *ssl_fingerprint_file == '\0') {
	dbprintf(_("No ssl-ca-cert-file or ssl-fingerprint-file set\n"));
	return;
    }

    /* Set to require peer (client) certificate verification */
    SSL_CTX_set_verify(rc->ctx, SSL_VERIFY_PEER, NULL);

    /* Set the verification depth to 1 */
    SSL_CTX_set_verify_depth(rc->ctx,1);

    rc->ssl = SSL_new(rc->ctx);
    if (!rc->ssl) {
	dbprintf(_("SSL_new failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	return;
    }
    SSL_set_accept_state(rc->ssl);

    /* Assign the socket into the SSL structure (SSL and socket without BIO) */
    SSL_set_fd(rc->ssl, in);

    /* Perform SSL Handshake on the SSL server */
    err = SSL_accept(rc->ssl);
    if (err == -1) {
	dbprintf(_("SSL_accept failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	return;
    }

    /* Get the server's certificate (optional) */
    client_cert = SSL_get_peer_certificate (rc->ssl);

    if (client_cert == NULL) {
	dbprintf(_("client have no certificate\n"));
	return;
    } else {
        char *str;

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        auth_debug(1, _("\t subject: %s\n"), str);
        amfree (str);
 
        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        auth_debug(1, _("\t issuer: %s\n"), str);
        amfree(str);

	str = validate_fingerprints(client_cert, ssl_fingerprint_file);
	if (str) {
	    dbprintf("%s\n", str);
	    amfree(str);
	    return;
	}
	X509_free(client_cert);
    }
    sec_tcp_conn_read(rc);
}

/*
 * Forks a ssl to the host listed in rc->hostname
 * Returns negative on error, with an errmsg in rc->errmsg.
 */
static int
runssl(
    struct sec_handle *	rh,
    in_port_t port,
    char *ssl_fingerprint_file,
    char *ssl_cert_file,
    char *ssl_key_file,
    char *ssl_ca_cert_file)
{
    int		     server_socket;
    in_port_t	     my_port;
    struct tcp_conn *rc = rh->rc;
    int              err;
    X509            *server_cert;

    set_root_privs(1);

    server_socket = stream_client_privileged(rc->hostname,
				     port,
				     STREAM_BUFSIZE,
				     STREAM_BUFSIZE,
				     &my_port,
				     0);
    set_root_privs(0);

    if(server_socket < 0) {
	security_seterror(&rh->sech,
	    "%s", strerror(errno));
	
	return -1;
    }

    if(my_port >= IPPORT_RESERVED) {
	security_seterror(&rh->sech,
			  _("did not get a reserved port: %d"), my_port);
	return -1;
    }

    rc->read = rc->write = server_socket;

    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();

    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();

    /* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
    rc->meth = SSLv3_method();

    /* Create an SSL_CTX structure */
    rc->ctx = SSL_CTX_new(rc->meth);
    if (!rc->ctx) {
	security_seterror(&rh->sech, "%s",
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }
    SSL_CTX_set_mode(rc->ctx, SSL_MODE_AUTO_RETRY);

    if (ssl_cert_file && *ssl_cert_file != '\0') {
dbprintf("load cert file\n");
        /* Load the client certificate into the SSL_CTX structure */
        if (SSL_CTX_use_certificate_file(rc->ctx, ssl_cert_file,
				         SSL_FILETYPE_PEM) <= 0) {
	    security_seterror(&rh->sech, "%s",
			      ERR_error_string(ERR_get_error(), NULL));
	    return -1;
        }
    } else {
	security_seterror(&rh->sech, "no ssl-cert-file defined");
	return -1;
    }

    if (ssl_key_file && *ssl_key_file != '\0') {
dbprintf("load key file\n");
        /* Load the private-key corresponding to the client certificate */
        if (SSL_CTX_use_PrivateKey_file(rc->ctx, ssl_key_file,
				        SSL_FILETYPE_PEM) <= 0) {
	    security_seterror(&rh->sech, "%s",
			      ERR_error_string(ERR_get_error(), NULL));
	    return -1;
        }
    } else {
	security_seterror(&rh->sech, "no ssl-key-file defined");
	return -1;
    }

    /* Check if the client certificate and private-key matches */
    if (!SSL_CTX_check_private_key(rc->ctx)) {
	security_seterror(&rh->sech,
		_("Private key does not match the certificate public key"));
	return -1;
    }

    if (ssl_ca_cert_file && *ssl_ca_cert_file != '\0') {
dbprintf("load ca cert file\n");
        /* Load the RSA CA certificate into the SSL_CTX structure */
        /* This will allow this client to verify the server's     */
        /* certificate.                                           */
        if (!SSL_CTX_load_verify_locations(rc->ctx, ssl_ca_cert_file, NULL)) {
	    security_seterror(&rh->sech, "%s",
			      ERR_error_string(ERR_get_error(), NULL));
	    return -1;
        }
    } else if (!ssl_fingerprint_file || *ssl_fingerprint_file == '\0') {
	security_seterror(&rh->sech,
		_("ssl-ca-cert-file or ssl-fingerprint-file must be set."));
	return -1;
    }

    /* Set flag in context to require peer (server) certificate */
    /* verification */
    SSL_CTX_set_verify(rc->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(rc->ctx, 1);

    /* ----------------------------------------------- */
    rc->ssl = SSL_new(rc->ctx);
    if (!rc->ssl) {
	security_seterror(&rh->sech, _("SSL_new failed"));
	return -1;
    }
    SSL_set_connect_state(rc->ssl);

    /* Assign the socket into the SSL structure (SSL and socket without BIO) */
    SSL_set_fd(rc->ssl, server_socket);

    /* Perform SSL Handshake on the SSL client */
    err = SSL_connect(rc->ssl);
    if (err == -1) {
	security_seterror(&rh->sech, "%s",
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }

    /* Get the server's certificate (optional) */
    server_cert = SSL_get_peer_certificate (rc->ssl);

    if (server_cert == NULL) {
	security_seterror(&rh->sech, _("client have no certificate"));
	return -1;
    } else {
        char *str;

        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        auth_debug(1, _("\t subject: %s\n"), str);
        amfree (str);
 
        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        auth_debug(1, _("\t issuer: %s\n"), str);
        amfree(str);

	str = validate_fingerprints(server_cert, ssl_fingerprint_file);
	if (str) {
	    security_seterror(&rh->sech, "%s", str);
	    amfree(str);
	    return -1;
	}

	X509_free (server_cert);
    }
    
    return 0;
}

static ssize_t
ssl_data_write(
    void         *c,
    struct iovec *iov,
    int           iovcnt)
{
    struct tcp_conn *rc = c;
    int              i;
    int              size;

dbprintf("ssl_data_write\n");
    size = 0;
    for (i=0; i < iovcnt; i++) {
	size += SSL_write(rc->ssl, iov[i].iov_base, iov[i].iov_len);
    }
dbprintf("ssl_data_write %d\n", size);
    return size;
    //return full_writev(rc->write, iov, iovcnt);
}

static ssize_t
ssl_data_read(
    void    *c,
    void    *buf,
    ssize_t  size)
{
    struct tcp_conn *rc = c;
    int              result;

dbprintf("ssl_data_read:: %d\n", (int)size);
//    return net_read(rc->read, buf, size, 0);
    result = 0;
    while(result < size) {
        result += SSL_read(rc->ssl, buf+result, size-result);
    }
dbprintf("ssl_data_read %d\n", result);
    return result;
}
