import M2Crypto
import signing.jwt as jwt
import os
import SimpleHTTPServer
import SocketServer
import unittest
from multiprocessing import Process
import time
import json
import atexit

from signing.tests import (SigningTest, StupidRequest, HTTP_PORT,
                           ROOT_PRIV_PATH, ROOT_PUB_PATH, ISSUER_URL)
from keycert import run

HTTPD = None

def generate_root(bits=2048, expires=24*60*60, keyid=None, priv_path=None,
                  pub_path=None):
    """For generating test root ceritifcates"""

    if keyid is None:
        keyid = ISSUER_URL
    if priv_path is None:
        priv_path = ROOT_PRIV_PATH
    if pub_path is None:
        pub_path = ROOT_PUB_PATH

    def NoOp(): pass
    rsaObj = M2Crypto.RSA.gen_key(bits, 0x10001, NoOp)

    # Create the JWK from the pubkey
    juke = dict(jwk=[ dict(alg="RSA", use='sig', kid=keyid,
                           exp=jwt.base64url_encode(rsaObj.pub()[0][4:]),
                           mod=jwt.base64url_encode(rsaObj.pub()[1][4:])) ])

    with open(priv_path, 'w') as f:
        f.write(rsaObj.as_pem(None))
    with open(pub_path, 'w') as f:
        f.write(json.dumps(juke))

    return True


def serve_http():
    listen = ("127.0.0.1", HTTP_PORT)
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(listen, handler)
    httpd.serve_forever()


# Setup a simple HTTP server to use with keycert.py checks
os.chdir("signing/tests")
# Generate test run root key pair
generate_root()

# Start up a webserver on localhost
HTTPD = Process(target=serve_http)
HTTPD.start()

atexit.register(HTTPD.terminate)


class GenerateTest(unittest.TestCase):

    def test_0_newkey(self):
        cmd = 'newkey test-%s' % time.strftime('%F')
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_1_certify(self):
        cmd = "--environment dev certify --signing-key=%s --issuer=%s " \
              "--keyid=test_1_certify test-%s.pem" % (ROOT_PRIV_PATH, ISSUER_URL,
                                                      time.strftime('%F'))
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_2_newcert(self):
        cmd = "--environment dev newcert --signing-key=%s " \
              "--issuer=%s --keyid=dev-testing" % (ROOT_PRIV_PATH, ISSUER_URL)
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_3_pem2jwk(self):
        cmd = "pem2jwk --keyid=test-%s-pem2jwk --jwk=test-%s-pem2jwk " \
              "test-%s.pem" % tuple([time.strftime('%F') for i in (0, 1, 2)])
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_4_dateparse(self):
        pass


