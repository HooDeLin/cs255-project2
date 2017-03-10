import socket
import sys
from OpenSSL import SSL

DEFAULT_HTTPS_PORT = 443
READ_BUFFER_SIZE = 2048
HEADER_DELIMITER = "\r\n\r\n"


def build_get_request(host, path):
    return '''GET %s HTTP/1.0\r\n
    Host: %s\r\n
    Accept: */*\r\n
    User-Agent: secure-curl\r\n
    Connection: close\r\n\r\n''' % (path if len(path) > 0 else "/", host)


def setup_context(tls_version, cipher_list):
    # TODO: Process input arguments and set appropriate context settings here
    context = SSL.Context(tls_version)
    context.set_cipher_list(cipher_list)
    return context


def setup_connection(url, tls_version, cipher_list):
    context = setup_context(tls_version, cipher_list)
    connection = SSL.Connection(
        context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    port = url.port if (url.port is not None) else DEFAULT_HTTPS_PORT
    connection.set_tlsext_host_name(url.hostname)

    try:
        connection.connect((url.hostname, port))
    except socket.error:
        sys.exit('Connection failed')

    connection.set_connect_state()

    try:
        connection.do_handshake()
    except Exception:
        sys.exit('SSL Handshake failed')
    return connection


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


def connect_and_download(url, settings):
    # TODO: I haven't tried running it yet, need to test whether there's any bug here
    connection = setup_connection(url, settings["tls_version"], settings["cipher_list"])
    # Get certificate from the connection
    # Check with crlfile or cacert or pinnedcertificate
    # Remember that pinnedcertificate overrides crlfile or cacert
    # Also check allow_stale_certs
    send_get_request(connection, url)
    full_response = read_response(connection)
    close_connection(connection)

    header, body = full_response.split(HEADER_DELIMITER, 1)
    # print header
    print body
