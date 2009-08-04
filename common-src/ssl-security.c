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
static ssize_t ssl_data_read(void *c, void *bug, size_t size);
static void init_ssl(void);

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
                  char *ssl_key_file, char *ssl_ca_cert_file,
                  char *ssl_cipher_list, int ssl_check_certificate_host);


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
    char *ssl_cipher_list = NULL;
    int   ssl_check_certificate_host = 1;

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
    rh->rc->need_priv_port = 0;

    if (rh->rs == NULL)
	goto error;

    amfree(rh->hostname);
    rh->hostname = stralloc(rh->rs->rc->hostname);

    if (conf_fn) {
	service = conf_fn("client_port", datap);
	if (strlen(service) <= 1)
	    service = AMANDA_SERVICE_NAME;
	dbprintf("Connecting to service '%s'\n", service);
	ssl_fingerprint_file = conf_fn("ssl_fingerprint_file", datap);
	ssl_cert_file        = conf_fn("ssl_cert_file", datap);
	ssl_key_file         = conf_fn("ssl_key_file", datap);
	ssl_ca_cert_file     = conf_fn("ssl_ca_cert_file", datap);
	ssl_cipher_list      = conf_fn("ssl_cipher_list", datap);
	ssl_check_certificate_host =
			    atoi(conf_fn("ssl_check_certificate_host", datap));
    } else {
	service = AMANDA_SERVICE_NAME;
    }

    port = find_port_for_service(service, "tcp");
    if (port == 0) {
	security_seterror(&rh->sech, _("%s/tcp unknown protocol"), service);
	goto error;
    }

    /*
     * We need to open a new connection.
     */
    if(rh->rc->read == -1) {
	if (runssl(rh, port, ssl_fingerprint_file, ssl_cert_file, ssl_key_file,
		   ssl_ca_cert_file, ssl_cipher_list,
		   ssl_check_certificate_host) < 0)
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

static char *validate_fingerprints(X509 *cert, char *ssl_fingerprint_file);

static char *
validate_fingerprints(
    X509 *cert,
    char *ssl_fingerprint_file)
{
    FILE *fingers;
    char fingerprint[32768];
    char *errmsg = NULL;

    unsigned char  md5[EVP_MAX_MD_SIZE + 1];
    unsigned int   len_md5;
    const EVP_MD  *evp_md5;
    char *md5_fingerprint;
    unsigned char  sha1[EVP_MAX_MD_SIZE + 1];
    unsigned int   len_sha1;
    const EVP_MD  *evp_sha1;
    char *sha1_fingerprint;
    char *fp;
    unsigned int   i;

    const char *md5_const  = "MD5 Fingerprint=";
    const char *sha1_const = "SHA1 Fingerprint=";
    const size_t md5_const_len = strlen(md5_const);
    const size_t sha1_const_len = strlen(sha1_const);

    if (ssl_fingerprint_file == NULL) {
	dbprintf("No fingerprint_file set\n");
	return NULL;
    }

    evp_md5 = EVP_get_digestbyname("MD5");
    if (!evp_md5) {
	auth_debug(1, _("EVP_get_digestbyname(MD5) failed"));
    }
    if (!X509_digest(cert, evp_md5, md5, &len_md5)) {
	auth_debug(1, _("cannot get MD5 digest"));
    }

    md5_fingerprint  = malloc(len_md5*3 + 1);
    fp = md5_fingerprint;
    for (i=0; i < len_md5; i++) {
	snprintf(fp, 4, "%02X:", (unsigned) md5[i]);
	fp+=3;
    }
    /* remove latest ':' */
    fp --;
    *fp = '\0';
    auth_debug(1, _("md5: %s\n"), md5_fingerprint);

    evp_sha1 = EVP_get_digestbyname("SHA1");
    if (!evp_sha1) {
	auth_debug(1, _("EVP_get_digestbyname(SHA1) failed"));
    }
    if (!X509_digest(cert, evp_sha1, sha1, &len_sha1)) {
	auth_debug(1, _("cannot get SHA1 digest"));
    }

    sha1_fingerprint  = malloc(len_sha1*3 + 1);
    fp = sha1_fingerprint;
    for (i=0; i < len_sha1; i++) {
	snprintf(fp, 4, "%02X:", (unsigned) sha1[i]);
	fp+=3;
    }
    /* remove latest ':' */
    fp --;
    *fp = '\0';
    auth_debug(1, _("sha1: %s\n"), sha1_fingerprint);

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
	if (strncmp(md5_const, fingerprint, md5_const_len) == 0) {
	    if (strcmp(md5_fingerprint, fingerprint+md5_const_len) == 0) {
		dbprintf("MD5 fingerprint '%s' match\n", md5_fingerprint);
		return NULL;
	    }
	} else if (strncmp(sha1_const, fingerprint, sha1_const_len) == 0) {
	    if (strcmp(sha1_fingerprint, fingerprint+sha1_const_len) == 0) {
		dbprintf("SHA1 fingerprint '%s' match\n", sha1_fingerprint);
		return NULL;
	    }
	}
	auth_debug(1, _("Fingerprint '%s' doesn't match\n"), fingerprint);
    }
    return g_strdup_printf("No fingerprint match");;
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
    char *ssl_cipher_list      = conf_fn("ssl_cipher_list", datap);
    int   ssl_check_host       = atoi(conf_fn("ssl_check_host", datap));
    int   ssl_check_certificate_host = atoi(conf_fn("ssl_check_certificate_host", datap));

    if (!ssl_cert_file) {
	dbprintf(_("ssl-cert-file must be set in amanda-client.conf\n"));
	return;
    }

    if (!ssl_key_file) {
	dbprintf(_("ssl-key-file must be set in amanda-client.conf\n"));
	return;
    }

    if (!ssl_ca_cert_file) {
	dbprintf(_("ssl_ca_cert_file must be set in amanda-client.conf\n"));
	return;
    }

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

    if (ssl_check_host && check_name_give_sockaddr(hostname,
				 (struct sockaddr *)&sin, &errmsg) < 0) {
	amfree(errmsg);
	return;
    }

    rc = sec_tcp_conn_get(hostname, 0);
    rc->recv_security_ok = &bsd_recv_security_ok;
    rc->prefix_packet = &bsd_prefix_packet;
    rc->need_priv_port = 0;
    copy_sockaddr(&rc->peer, &sin);
    rc->read = in;
    rc->write = out;
    rc->accept_fn = fn;
    rc->driver = driver;
    rc->conf_fn = conf_fn;
    rc->datap = datap;

    init_ssl();

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

    if (ssl_cipher_list) {
	dbprintf("Set ssl_cipher_list to %s\n", ssl_cipher_list);
	if (SSL_CTX_set_cipher_list(rc->ctx, ssl_cipher_list) == 0) {
	    dbprintf(_("SSL_CTX_set_cipher_list failed: %s\n"),
		     ERR_error_string(ERR_get_error(), NULL));
	    return;
	}
    }

    /* Load the server certificate into the SSL_CTX structure */
    dbprintf(_("Loading ssl-cert-file certificate %s\n"), ssl_cert_file);
    if (SSL_CTX_use_certificate_file(rc->ctx, ssl_cert_file,
				     SSL_FILETYPE_PEM) <= 0) {
	dbprintf(_("Load ssl-cert-file failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	return;
    }

    /* Load the private-key corresponding to the server certificate */
    dbprintf(_("Loading ssl-key-file private-key %s\n"), ssl_key_file);
    if (SSL_CTX_use_PrivateKey_file(rc->ctx, ssl_key_file,
				    SSL_FILETYPE_PEM) <= 0) {
	dbprintf(_("Load ssl-key-file failed: %s\n"),
		 ERR_error_string(ERR_get_error(), NULL));
	return;
    }

    if (ssl_ca_cert_file) {
        /* Load the RSA CA certificate into the SSL_CTX structure */
	dbprintf(_("Loading ssl-ca-cert-file ca certificate %s\n"),
		 ssl_ca_cert_file);
        if (!SSL_CTX_load_verify_locations(rc->ctx, ssl_ca_cert_file, NULL)) {
	    dbprintf(_("Load ssl-ca-cert-file failed: %s\n"),
		     ERR_error_string(ERR_get_error(), NULL));
	    return;
        }

	/* Set to require peer (client) certificate verification */
	SSL_CTX_set_verify(rc->ctx, SSL_VERIFY_PEER, NULL);

	/* Set the verification depth to 1 */
	SSL_CTX_set_verify_depth(rc->ctx,1);
    }

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
	dbprintf(_("client doesn't sent a certificate\n"));
	return;
    } else {
        char *str;

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        auth_debug(1, _("\t subject: %s\n"), str);
        amfree (str);
 
        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        auth_debug(1, _("\t issuer: %s\n"), str);
        amfree(str);

	if (ssl_check_certificate_host) {
	    X509_NAME *x509_name = X509_get_subject_name(client_cert);
	    int loc = -1;
	    loc = X509_NAME_get_index_by_NID(x509_name, NID_commonName, loc);
	    if (loc != -1) {
		X509_NAME_ENTRY *x509_entry = X509_NAME_get_entry(x509_name, loc);
		ASN1_STRING *asn1_string = X509_NAME_ENTRY_get_data(x509_entry);
		char *cert_hostname =  (char *)ASN1_STRING_data(asn1_string);
		auth_debug(1, "common_name: %s\n", cert_hostname);

		if (check_name_give_sockaddr((char*)cert_hostname,
				 (struct sockaddr *)&sin, &errmsg) < 0) {
		    dbprintf("Common name of certicate (%s) doesn't resolv to IP (%s)\n", cert_hostname, str_sockaddr(&sin));
		    amfree(errmsg);
		    return;
		}
	    } else {
		dbprintf("Certificate have no common name\n");
		return;
	    }
	}

	if (ssl_fingerprint_file) {
	    str = validate_fingerprints(client_cert, ssl_fingerprint_file);
	    if (str) {
		dbprintf("%s\n", str);
		amfree(str);
		return;
	    }
	}
	X509_free(client_cert);
    }

    dbprintf(_("SSL_cipher: %s\n"), SSL_get_cipher(rc->ssl));

    sec_tcp_conn_read(rc);
}

/*
 * Open a ssl connection to the host listed in rc->hostname
 * Returns negative on error, with an errmsg in rc->errmsg.
 */
static int
runssl(
    struct sec_handle *	rh,
    in_port_t port,
    char *ssl_fingerprint_file,
    char *ssl_cert_file,
    char *ssl_key_file,
    char *ssl_ca_cert_file,
    char *ssl_cipher_list,
    int   ssl_check_certificate_host)
{
    int		     server_socket;
    in_port_t	     my_port;
    struct tcp_conn *rc = rh->rc;
    int              err;
    X509            *server_cert;
    sockaddr_union   sin;
    socklen_t_equiv  len;

    if (!ssl_key_file) {
	security_seterror(&rh->sech, _("ssl-key-file must be set"));
	return -1;
    }

    if (!ssl_cert_file) {
	security_seterror(&rh->sech, _("ssl-cert-file must be set"));
	return -1;
    }

    server_socket = stream_client(rc->hostname,
				  port,
				  STREAM_BUFSIZE,
				  STREAM_BUFSIZE,
				  &my_port,
				  0);

    if(server_socket < 0) {
	security_seterror(&rh->sech,
	    "%s", strerror(errno));
	
	return -1;
    }

    rc->read = rc->write = server_socket;

    len = sizeof(sin);
    if (getpeername(server_socket, (struct sockaddr *)&sin, &len) < 0) {
	security_seterror(&rh->sech, _("getpeername returned: %s\n"), strerror(errno));
	return -1;
    }
    copy_sockaddr(&rc->peer, &sin);

    init_ssl();

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

    if (ssl_cipher_list) {
	dbprintf("Set ssl_cipher_list to %s\n", ssl_cipher_list);
	if (SSL_CTX_set_cipher_list(rc->ctx, ssl_cipher_list) == 0) {
	    security_seterror(&rh->sech, "%s",
		              ERR_error_string(ERR_get_error(), NULL));
	    return -1;
	}
    }

    /* Load the private-key corresponding to the client certificate */
    dbprintf("Loading ssl-key-file private-key %s\n", ssl_key_file);
    if (SSL_CTX_use_PrivateKey_file(rc->ctx, ssl_key_file,
				    SSL_FILETYPE_PEM) <= 0) {
	security_seterror(&rh->sech, "%s",
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }

    /* Load the server certificate into the SSL_CTX structure */
    dbprintf("Loading ssl-cert-file certificate %s\n", ssl_cert_file);
    if (SSL_CTX_use_certificate_file(rc->ctx, ssl_cert_file,
				     SSL_FILETYPE_PEM) <= 0) {
	security_seterror(&rh->sech, "%s",
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }

    /* Check if the client certificate and private-key matches */
    if (ssl_cert_file) {
	if (!SSL_CTX_check_private_key(rc->ctx)) {
	security_seterror(&rh->sech,
		_("Private key does not match the certificate public key"));
	return -1;
	}
    }

    if (ssl_ca_cert_file) {
        /* Load the RSA CA certificate into the SSL_CTX structure */
        /* This will allow this client to verify the server's     */
        /* certificate.                                           */
	dbprintf("Loading ssl-ca-cert-file ca %s\n", ssl_ca_cert_file);
        if (!SSL_CTX_load_verify_locations(rc->ctx, ssl_ca_cert_file, NULL)) {
	    security_seterror(&rh->sech, "%s",
			      ERR_error_string(ERR_get_error(), NULL));
	    return -1;
        }
    } else {
	dbprintf(_("no ssl-ca-cert-file defined\n"));
    }

    /* Set flag in context to require peer (server) certificate */
    /* verification */
    if (ssl_ca_cert_file) {
	dbprintf("Enabling certification verification\n");
	SSL_CTX_set_verify(rc->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(rc->ctx, 1);
    } else {
	dbprintf("Not enabling certification verification\n");
    }

    /* ----------------------------------------------- */
    rc->ssl = SSL_new(rc->ctx);
    if (!rc->ssl) {
	security_seterror(&rh->sech, _("SSL_new failed: %s"),
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }
    SSL_set_connect_state(rc->ssl);

    /* Assign the socket into the SSL structure (SSL and socket without BIO) */
    SSL_set_fd(rc->ssl, server_socket);

    /* Perform SSL Handshake on the SSL client */
    err = SSL_connect(rc->ssl);
    if (err == -1) {
	security_seterror(&rh->sech, _("SSL_connect failed: %s"),
			  ERR_error_string(ERR_get_error(), NULL));
	return -1;
    }

    /* Get the server's certificate (optional) */
    server_cert = SSL_get_peer_certificate(rc->ssl);

    if (server_cert == NULL) {
	security_seterror(&rh->sech, _("server have no certificate"));
	return -1;
    } else {
        char *str;

        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        auth_debug(1, _("\t subject: %s\n"), str);
        amfree (str);
 
        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        auth_debug(1, _("\t issuer: %s\n"), str);
        amfree(str);

	if (ssl_check_certificate_host) {
	    int   loc = -1;
	    char *errmsg = NULL;
	    X509_NAME *x509_name = X509_get_subject_name(server_cert);

	    loc = X509_NAME_get_index_by_NID(x509_name, NID_commonName, loc);
	    if (loc != -1) {
		X509_NAME_ENTRY *x509_entry = X509_NAME_get_entry(x509_name, loc);
		ASN1_STRING *asn1_string = X509_NAME_ENTRY_get_data(x509_entry);
		char *cert_hostname =  (char *)ASN1_STRING_data(asn1_string);
		auth_debug(1, "common_name: %s\n", cert_hostname);

		if (check_name_give_sockaddr((char*)cert_hostname,
				 (struct sockaddr *)&rc->peer, &errmsg) < 0) {
		    security_seterror(&rh->sech,
		       _("Common name of certicate (%s) doesn't resolv to IP (%s): %s"),
		       cert_hostname, str_sockaddr(&rc->peer), errmsg);
		    amfree(errmsg);
		    return -1;
		}
		auth_debug(1,
		         _("Certificate common name (%s) resolve to IP (%s)\n"),
			 cert_hostname, str_sockaddr(&rc->peer));
	    } else {
		security_seterror(&rh->sech,
				  _("Certificate have no common name"));
		dbprintf("Certificate have no common name\n");
		return -1;
	    }
	}

	if (ssl_fingerprint_file) {
	    str = validate_fingerprints(server_cert, ssl_fingerprint_file);
	    if (str) {
		security_seterror(&rh->sech, "%s", str);
		amfree(str);
		return -1;
	    }
	}
	X509_free (server_cert);
    }
    
    dbprintf(_("SSL_cipher: %s\n"), SSL_get_cipher(rc->ssl));

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

    size = 0;
    for (i=0; i < iovcnt; i++) {
	size += SSL_write(rc->ssl, iov[i].iov_base, iov[i].iov_len);
    }
    return size;
    //return full_writev(rc->write, iov, iovcnt);
}

static ssize_t
ssl_data_read(
    void    *c,
    void    *buf,
    size_t   size)
{
    struct tcp_conn *rc = c;
    int              result = 0;
    int              out_size;

    out_size = 0;
    while(out_size < (ssize_t)size) {
        result = SSL_read(rc->ssl, buf+result, size-result);
	if (result > 0)
	    out_size += result;
	else if (out_size > 0)
	    return out_size;
	else
	    return result;
    }
    return result;
}

static void
init_ssl(void)
{
    static int init_done = 0;

    if (init_done == 0) {
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	init_done = 1;
    }
}
