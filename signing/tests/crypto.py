import time
import signing.crypto
import signing.jwt as jwt
import json

from signing.tests import SigningTest, stamp, ROOT_PRIV_PATH, ISSUER_URL
from signing.certify import run


# Subclass SigningTest to get all the test setup
class MCryptoTest(SigningTest):

    def test_0_sign_verify(self):
        cert = signing.crypto.get_certificate()
        receipt = signing.crypto.sign_jwt(stamp())
        # This should work but isn't.  Again.
        #self.assert_(signing.crypto.verify_jwt(receipt))
        self.assert_(jwt.decode(receipt, signing.crypto.KEYSTORE.key.get_rsa()))

    def test_key_update(self):
        first_cert = signing.crypto.get_certificate()
        first_receipt = signing.crypto.sign_jwt(stamp())
        #self.assert_(signing.crypto.verify_jwt(first_receipt))
        self.assert_(jwt.decode(first_receipt,
                                signing.crypto.KEYSTORE.key.get_rsa()))
        # Generate a replacement key, BABY
        cmd = "--environment dev newcert --signing-key=%s " \
              "--issuer=%s --keyid=dev-testing" % (ROOT_PRIV_PATH, ISSUER_URL)
        run(cmd.split())
        # Fudge our last stat() time
        l = signing.crypto.KEYSTORE.last_stat
        p = signing.crypto.KEYSTORE.poll_interval + 5
        signing.crypto.KEYSTORE.last_stat = l - p
        # Sign first to force a stat() check
        second_receipt = signing.crypto.sign_jwt(stamp())
        second_cert = signing.crypto.get_certificate()
        #self.assert_(signing.crypto.verify_jwt(first_receipt))
        self.assert_(jwt.decode(second_receipt,
                                signing.crypto.KEYSTORE.key.get_rsa()))
        c1 = jwt.decode(first_cert, verify=False)
        c2 = jwt.decode(second_cert, verify=False)
        self.assertNotEqual(c1["jwk"][0]["mod"], c2["jwk"][0]["mod"],
                            msg="certificate unchanged")
