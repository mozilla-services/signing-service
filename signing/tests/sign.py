import time

from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict
from webtest import TestApp
from signing.tests import SigningTest, StupidRequest, stamp
from signing.views import sign

from signing.tests.generate import generate_root


class SignTest(SigningTest):

    def test_sign(self):
        def req(): return StupidRequest(path=self.path, post=stamp())
        request = req()
        #self.assert_(HTTPBadRequest, sign, request)
        from pprint import pprint
        pprint(sign(request))
        generate_root()
        pprint(sign(reqeuest))

#    def test_sign_key_switch(self):
#        self.test_sign()
#        generate_root()
#        self.test_sign()
