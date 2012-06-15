import M2Crypto
import jwt
import os
import SimpleHTTPServer
import SocketServer
from multiprocessing import Process
import time

from signing.tests import SigningTest, StupidRequest
from keycert import run

M2Crypto.Rand.rand_seed(os.urandom(1024))

PORT = 63634

def generate_root(bits, expires, keyid):
    """For generating test root ceritifcates"""

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


class GenerateTest(unittest.TestCase):

    def setUp(self):
        self.root_priv_path = 'test-root-key.pem'
        self.root_pub_path = 'test-root-pub.jwk'
        self.issuer_url = 'http://localhost:%d/%s' % (PORT, self.root_pub_path)
        # Generate test run root key
        self.root_priv, self.root_pub = generate_root(2048, 24 * 60 * 60,
                                                      self.issuer_url)
        with open(self.root_priv_path, 'w') as f:
            f.write(root_priv)
        with open(self.root_pub_path, 'w') as f:
            f.write(root_pub)
        # Start up a webserver on localhost
        self.httpd = Process(target=serve_http)
        self.httpd.start()

    def tearDown(self):
        self.httpd.stop()

    def test_newkey(self):
        cmd = 'newkey --keyid=test-%s' % time.strftime('%F')
        self.assert_(run(cmd.split()))

    def test_certify(self):
        cmd = "certify --signing-key='%s' --issuer='%s'" % (self.root_priv_path,
                                                            self.issuer_url)
        self.assert_(run(cmd.split()))

    def test_newcert(self):
        cmd = "newcert --signing-key='%s' --issuer='%s'" % (self.root_priv_path,
                                                            self.issuer_url)
        self.assert_(run(cmd.split()))

    def test_pem2jwk(self):
        cmd = 'pem2jwk --keyid=test-%s-pem2jwk --jwk=test-%s-pem2jwk' \
            % (time.strftime('%F'), time.strftime('%F'))
        self.assert_(run(cmd.split()))

    def test_dateparse(self):
        pass
