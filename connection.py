import socket
import sys
from OpenSSL import SSL
import re

DEFAULT_HTTPS_PORT = 443
READ_BUFFER_SIZE = 2048
HEADER_DELIMITER = "\r\n\r\n"
WILDCARD_HOSTNAME_RE = re.compile(r'^[^\.]+?\.')
X509_V_ERR_CERT_HAS_EXPIRED = 10


def build_get_request(host, path):
    return '''GET %s HTTP/1.0\r\n
    Host: %s\r\n
    Accept: */*\r\n
    User-Agent: secure-curl\r\n
    Connection: close\r\n\r\n''' % (path if len(path) > 0 else "/", host)

def setup_context(settings):
    context = SSL.Context(settings["tls_version"])
    if "cipher" in settings:
        try:
            context.set_cipher_list(settings["cipher"])
        except:
            sys.exit("Cipher " + settings["cipher"] + " is not supported.")
    return context


def setup_connection(settings):
    context = setup_context(settings)
    connection = SSL.Connection(
        context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    port = settings["url"].port if (settings["url"].port is not None) else DEFAULT_HTTPS_PORT
    connection.set_tlsext_host_name(settings["url"].hostname)
    context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       cert_validate_callback)

    try:
        connection.connect((settings["url"].hostname, port))
    except socket.error:
        sys.exit('Connection failed')

    connection.set_connect_state()

    try:
        connection.do_handshake()
    except Exception:
        sys.exit('SSL Handshake failed')

    server_cert = connection.get_peer_certificate()

    validate_certificate_subject(server_cert, settings["url"].hostname)

    return connection


def validate_certificate_subject(cert, hostname):
    alt_names = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if (ext.get_short_name() == "subjectAltName"):
            alt_names_as_string = str(ext)
            alt_names = alt_names + map(lambda x: x[4:],
                                        alt_names_as_string.split(', '))

    # TODO: enhance wildcard matching to support "b*z.example.com"?
    cert_cn = cert.get_subject().CN.lower()
    hostname_with_wildcard = re.sub(WILDCARD_HOSTNAME_RE, '*.', hostname)
    accepted_names = set([hostname.lower(), hostname_with_wildcard.lower()])
    server_names = set([cert_cn] + alt_names)
    if not server_names & accepted_names:
        sys.exit("CN %s doesn't match any of %s" %
                 (server_names, accepted_names))


def cert_validate_callback(conn, cert, errno, depth, result):
    if errno == X509_V_ERR_CERT_HAS_EXPIRED:
        return False
    elif errno == 0:
        return True
    else:
        return False


def send_get_request(connection, url):
    try:
        request_string = build_get_request(url.hostname, url.path)
        connection.sendall(request_string)
    except SSL.Error:
        sys.exit('Connection failed')


def read_response(connection):
    input_buffer = []
    while 1:
        try:
            input_buffer.append(connection.recv(READ_BUFFER_SIZE))
        except SSL.Error:
            break
    return "".join(input_buffer)


def close_connection(connection):
    connection.shutdown()
    connection.close()


def connect_and_download(settings):
    connection = setup_connection(settings)
    # Get certificate from the connection
    # Check with crlfile or cacert or pinnedcertificate
    # Remember that pinnedcertificate overrides crlfile or cacert
    # Also check allow_stale_certs
    send_get_request(connection, settings["url"])
    full_response = read_response(connection)
    close_connection(connection)

    header, body = full_response.split(HEADER_DELIMITER, 1)
    # print header
    print body
