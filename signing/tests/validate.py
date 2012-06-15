from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict
from signing.validators import valid_receipt
from signing.tests import SigningTest, StupidRequest


class ValidateTest(SigningTest):

    def test_validate_malformed_json(self):
        request = StupidRequest(path=self.path,
                                post=dict(nascar=dict(self._template)))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

    def test_validate_issuer(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iss="Big Bob's Rodeo Dairy!"))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_nbf(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template, nbf=0))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          nbf=self.signing['iat'] - 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          nbf=self.signing['exp'] + 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_iat(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template, iat=0))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iat=self.signing['iat'] - 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iat=self.signing['exp'] + 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_user(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user='not a dict!'))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'taco',
                                                'value': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'email',
                                                'value': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'email',
                                                'value': 'hal@9000'}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)


    def test_validate_product(self):
        post=dict(self._template,
                  product='not a dict!')
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product='not a dict!'))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'gopher://yoyodyne-propulsion.com'}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'https://grumpybadgers.com',
                                                   'storedata': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'https://grumpybadgers.com',
                                                   'storedata': "Mr. A Square, Flatland"}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'https://grumpybadgers.com',
                                                   'storedata': 200.01}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)
