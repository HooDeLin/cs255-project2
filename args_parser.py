import argparse


def parse_args():
    # TODO: All these code should be in a parser block
    parser = argparse.ArgumentParser()
    parser.add_argument("--ciphers", help="SSL ciphers to use (SSL)")
    parser.add_argument("--tlsv1.0", help="Use TLSv1.0 (SSL)",
                        action="store_true")
    parser.add_argument("--tlsv1.1", help="Use TLSv1.1 (SSL)",
                        action="store_true")
    parser.add_argument("--tlsv1.2", help="Use TLSv1.2 (SSL)",
                        action="store_true")
    parser.add_argument("-3", "--sslv3", help="Use SSLv3 (SSL)",
                        action="store_true")
    parser.add_argument("--crlfile",
                        help="Get a CRL list in PEM format from given file",
                        type=file)
    parser.add_argument("--cacert",
                        help="CA certificate to verify peer against (SSL)",
                        type=file)
    parser.add_argument("--allow-stale-certs", type=int,
                        help="Allow Stale Certs")
    parser.add_argument("--pinnedcertificate", help="Pinned Certificate")
    parser.add_argument("url", help="https url")
    return vars(parser.parse_args())
