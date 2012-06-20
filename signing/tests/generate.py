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

from signing.tests import SigningTest, StupidRequest
from keycert import run

M2Crypto.Rand.rand_seed(os.urandom(1024))

PORT = 63634
HTTPD = None

def generate_root(bits, expires, keyid):
    """For generating test root ceritifcates"""

    def NoOp(): pass

    rsaObj = M2Crypto.RSA.gen_key(bits, 0x10001, NoOp)

    # Create the JWK from the pubkey
    juke = dict(jwk=[ dict(alg="RSA", use='sig', kid=keyid,
                           exp=jwt.base64url_encode(rsaObj.pub()[0][4:]),
                           mod=jwt.base64url_encode(rsaObj.pub()[1][4:])) ])

    return (rsaObj.as_pem(None), json.dumps(juke))


def serve_http():
    listen = ("127.0.0.1", PORT)
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(listen, handler)
    httpd.serve_forever()


# Setup a simple HTTP server to use with keycert.py checks
os.chdir("signing/tests")
root_priv_path = 'test-root-key.pem'
root_pub_path = 'test-root-pub.jwk'
issuer_url = 'http://localhost:%d/%s' % (PORT, root_pub_path)
# Generate test run root key
root_priv, root_pub = generate_root(2048, 24 * 60 * 60, issuer_url)
with open(root_priv_path, 'w') as f:
    f.write(root_priv)
with open(root_pub_path, 'w') as f:
    f.write(root_pub)
# Start up a webserver on localhost
HTTPD = Process(target=serve_http)
HTTPD.start()

atexit.register(HTTPD.terminate)


class GenerateTest(unittest.TestCase):

    def test_0_newkey(self):
        print "\n\n%s\n\n" % os.path.abspath(os.curdir)
        cmd = 'newkey test-%s' % time.strftime('%F')
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_1_certify(self):
        print "\n\n%s\n\n" % os.path.abspath(os.curdir)
        cmd = "--environment dev certify --signing-key=%s --issuer=%s " \
              "--keyid=test_1_certify test-%s.pem" % (root_priv_path, issuer_url,
                                                   time.strftime('%F'))
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_2_newcert(self):
        cmd = "--environment dev newcert --signing-key=%s " \
              "--issuer=%s --keyid=dev-testing" % (root_priv_path, issuer_url)
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_3_pem2jwk(self):
        cmd = 'pem2jwk --keyid=test-%s-pem2jwk --jwk=test-%s-pem2jwk test-%s.pem' \
            % (time.strftime('%F'), time.strftime('%F'), time.strftime('%F'))
        self.assertEqual(run(cmd.split()), None, msg=cmd)

    def test_4_dateparse(self):
        pass


