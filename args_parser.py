import sys
from urlparse import urlparse
import OpenSSL


def readPEM(filename, type):
    # 0 - crlfile
    # 1 - cert
    try:
        f = open(filename).read()

        if type == 0:
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM,
                                                 f)
            return crl_object.get_revoked()
        else:
            return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                   f)
    except:
        sys.exit("Unable to read file: " + filename)


def validate_url(url):
    if url.scheme != 'https':
        sys.exit("'%s' is not an https url" % url.geturl())


def parse_args(system_arguments):
    # According to https://piazza.com/class/ixqf7ryk3276hz?cid=324, url is always the last element
    url_string = system_arguments[-1]

    try:
        url = urlparse(url_string)
    except:
        sys.exit('Can\'t parse the url')
    validate_url(url)
    settings = {}
    settings["url"] = url
    settings["tls_version"] = OpenSSL.SSL.TLSv1_2_METHOD

    # First argument is ./scurl, last one is url
    argv = system_arguments[1:-1]
    tls_flag = {
        "--tlsv1.0": OpenSSL.SSL.TLSv1_METHOD,
        "--tlsv1.1": OpenSSL.SSL.TLSv1_1_METHOD,
        "--tlsv1.2": OpenSSL.SSL.TLSv1_2_METHOD,
        "--sslv3": OpenSSL.SSL.SSLv3_METHOD,
        "-3": OpenSSL.SSL.SSLv3_METHOD
    }
    supported_input = [
        "--ciphers", "--crlfile", "--cacert", "--allow-stale-certs",
        "--pinnedcertificate"
    ]
    runmode = ""
    for arg in argv:
        if runmode == "":
            if arg in tls_flag:
                settings["tls_version"] = tls_flag[arg]
            elif arg in supported_input:
                runmode = arg
            else:
                sys.exit("Unsupported flag: " + arg)
        else:
            # Previous arguments require an input
            if runmode == "--ciphers":
                settings["cipher"] = arg
            elif runmode == "--crlfile":
                settings["revoked_objects"] = readPEM(arg, 0)
            elif runmode == "--cacert":
                settings["cacert"] = readPEM(arg, 1)
                settings["cacert_file"] = arg
            elif runmode == "--allow-stale-certs":
                if arg.isdigit():
                    settings["allow-stale-certs"] = int(arg)
                else:
                    sys.exit(runmode + " must be an int")
            elif runmode == "--pinnedcertificate":
                settings["pinnedcertificate"] = readPEM(arg, 1)
            else:
                sys.exit(runmode + "requires an input")
            runmode = ""

    # Arguments are leave hanging
    if runmode != "":
        sys.exit(runmode + "is missing")

    return settings
