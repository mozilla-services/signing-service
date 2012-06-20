import unittest
import time
import os
import json
import M2Crypto

from pyramid import testing
from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict
from mozsvc.config import load_into_settings

from signing.validators import valid_receipt
from signing.views import sign_receipt
import signing.crypto
import signing.jwt as jwt

HTTP_PORT = 63634
ROOT_PRIV_PATH = 'test-root-key.pem'
ROOT_PUB_PATH = 'test-root-pub.jwk'
ISSUER_URL = 'http://localhost:%d/%s' % (HTTP_PORT, ROOT_PUB_PATH)

M2Crypto.Rand.rand_seed(os.urandom(1024))

class StupidRequest(testing.DummyRequest):
    """This is a stupid subclass so I can get a json_body property"""

    @property
    def json_body(self):
        return self.POST


class SigningTest(unittest.TestCase):

    def setUp(self):
        self.path = '/1.0/sign'
        self.config = testing.setUp()
        self.ini = os.path.join(os.path.dirname(__file__), 'signing-test.ini')
        settings = {}
        load_into_settings(self.ini, settings)
        self.config.add_settings(settings)
        self.config.include("signing")
        # All of that just for this
        signing.crypto.init(key=self.config.registry.settings['signing.keyfile'],
                            cert=self.config.registry.settings['signing.certfile'])

        self.signing = signing.crypto.KEYSTORE.cert_data
        self._template = dict(typ="purchase-receipt",
                              product={"url": "https://grumpybadgers.com",
                                       "storedata": "5169314356"},
                              user={"type": "email",
                                    "value": "pickles@example9.com"},
                              iss=signing.crypto.KEYSTORE.cert_data['iss'],
                              nbf=self.signing['iat'],
                              iat=self.signing['iat'],
                              detail="https://appstore.com/receipt/5169314356",
                              verify="https://appstore.com/verify/5169314356")

    def tearDown(self):
        testing.tearDown()


def stamp(when=time.time()):
    return  {
        "typ": "purchase-receipt",
        "product": {
            "url": "https://grumpybadgers.com",
            "storedata": "ARTFUL 5169314356"
            },
        "user": {
            "type": "email",
            "value": "pseud-123gBm51jc56s@idprovider.com"
            },
        "iss": "https://bananaphone.com",
        "nbf": when,
        "iat": when,
        "exp": when + (24 * 60 * 60),
        "detail": "https://appstore.com/receipt/5169314356",
        "verify": "https://appstore.com/verify/5169314356"
    }


from signing.tests.generate import GenerateTest
from signing.tests.validate import ValidateTest
from signing.tests.sign import SignTest
from signing.tests.crypto import MCryptoTest

