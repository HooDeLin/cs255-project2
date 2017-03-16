import socket
import sys
from OpenSSL import SSL
from datetime import datetime, timedelta
import re

DEFAULT_HTTPS_PORT = 443
READ_BUFFER_SIZE = 2048
HEADER_DELIMITER = "\r\n\r\n"
WILDCARD_HOSTNAME_RE = re.compile(r'^[^\.]+?\.')
X509_V_ERR_CERT_HAS_EXPIRED = 10

allow_stale_certs = 0
pinned_cert = None
crl = None


def build_get_request(host, path):
    return '''GET %s HTTP/1.0\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: secure-curl\r\nConnection: close\r\n\r\n''' % (path if len(path) > 0 else "/", host)


def setup_context(settings):
    context = SSL.Context(settings["tls_version"])
    if "cipher" in settings:
        try:
            context.set_cipher_list(settings["cipher"])
        except:
            sys.exit("Cipher " + settings["cipher"] + " is not supported.")

    context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       cert_validate_callback)

    if settings.get("cacert_file"):
        context.load_verify_locations(settings["cacert_file"])
    else:
        context.set_default_verify_paths()
    return context


def setup_connection(settings):
    context = setup_context(settings)
    connection = SSL.Connection(
        context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    port = settings["url"].port if (
        settings["url"].port is not None) else DEFAULT_HTTPS_PORT

    try:
        connection.connect((settings["url"].hostname, port))
    except socket.error:
        sys.exit('Connection failed')

    connection.set_tlsext_host_name(settings["url"].hostname)

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

    cert_cn = cert.get_subject().CN.lower()
    hostname_with_wildcard = re.sub(WILDCARD_HOSTNAME_RE, '*.', hostname)
    accepted_names = set([hostname.lower(), hostname_with_wildcard.lower()])
    server_names = set([cert_cn] + alt_names)
    if not server_names & accepted_names:
        sys.exit("CN %s doesn't match any of %s" %
                 (server_names, accepted_names))


def validate_pinned_cert(cert):
    server_cert_sha256 = cert.digest('sha256')
    pinned_cert_sha256 = pinned_cert.digest('sha256')
    return server_cert_sha256 == pinned_cert_sha256


def validate_cert_expiry(cert):
    cert_expiry = cert.get_notAfter()
    cert_expiry_date = datetime.strptime(cert_expiry, "%Y%m%d%H%M%SZ")
    now = datetime.now()
    allowed_delta = timedelta(days=allow_stale_certs)
    max_allowed_expiry = now - allowed_delta
    return cert_expiry_date >= max_allowed_expiry


def validate_against_crl(cert):
    cert_serial = int(cert.get_serial_number())
    revoked_serials = map(lambda x: int(x.get_serial(), 16), crl)
    return cert_serial not in revoked_serials


def cert_validate_callback(conn, cert, errno, depth, result):
    if pinned_cert:
        if depth == 0:
            return validate_pinned_cert(cert)
        else:
            return True
    else:
        # validate_against_crl() returns True when cert is OK,
        # in other words is NOT revoked
        if crl and not validate_against_crl(cert):
            return False

        if errno == X509_V_ERR_CERT_HAS_EXPIRED:
            if allow_stale_certs > 0:
                return validate_cert_expiry(cert)
            else:
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
    global allow_stale_certs
    global pinned_cert
    global crl
    allow_stale_certs = settings.get("allow-stale-certs")
    pinned_cert = settings.get("pinnedcertificate")
    crl = settings.get("revoked_objects")

    connection = setup_connection(settings)

    send_get_request(connection, settings["url"])
    full_response = read_response(connection)
    close_connection(connection)

    header, body = full_response.split(HEADER_DELIMITER, 1)
    sys.stdout.write(body)
