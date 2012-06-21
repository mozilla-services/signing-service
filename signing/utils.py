# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Signing Service
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Tilder (rtilder@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

#
# TODO:
#
#  - Add a --verbose option with more output
#

import sys, ConfigParser, struct
import M2Crypto, hashlib, json, requests
import signing.jwt as jwt

# Convert a JWK exponent or modulus from base64 URL safe encoded big endian
# byte string to an OpenSSL MPINT
def conv(a):
    __ = jwt.base64url_decode(a.encode('ascii'))
    return struct.pack('>I', len(__) + 1) + "\x00" + __


def check_keys(path):
    config = ConfigParser.ConfigParser()

    try:
        config.read(path)
    except ConfigParser.Error, e:
        print "INI file doesn't seem to be parseable by ConfigParser: %s" % e
        sys.exit(1)

    try:
        certfile = config.get('signing', 'certfile')
        keyfile = config.get('signing', 'keyfile')
    except ConfigParser.NoOptionError:
        print "keyfile or certfile options are missing from the signing " \
              "section of the config."
        sys.exit(1)

    # Load the private key
    try:
        priv = M2Crypto.RSA.load_key(keyfile)
    except Exception, e:
        print "Failed ot load private key:\n\t%s\n" % e
        sys.exit(1)

    # Buffer the file contents for later verification
    with open(certfile) as f:
        cert_data = f.read().encode('ascii')

    # Load but don't verify the JWK-in-a-JWT certificate.
    try:
        cert = jwt.decode(cert_data, verify=False)
    except Exception, e:
        print "Failed to decode JWT: %s" % e

    # Convert the JWK into a form usable by M2Crypto
    try:
        pub = M2Crypto.RSA.new_pub_key((conv(cert['jwk'][0]['exp']),
                                        conv(cert['jwk'][0]['mod'])))
    except Exception, e:
        print "Failed to create RSA object from certificate's JWK: %s" % e
        sys.exit(1)

    # Fetch the issuer's public key from the URL provided by the key
    try:
        print "Fetching root pub key from %s" % cert['iss']
        response = requests.get(cert['iss'])
        if response.status_code == 200:
            jwk = json.loads(response.text)
            root = M2Crypto.RSA.new_pub_key((conv(jwk['jwk'][0]['exp']),
                                             conv(jwk['jwk'][0]['mod'])))
    except requests.RequestException, e:
        print "Couldn't fetch %s: %s" % (cert['iss'], str(e))
        sys.exit(1)
    except Exception, e:
        print "Failed to convert fetched root pub key: %s" % e
        sys.exit(1)

    # Verify that our certificate has a valid signature
    try:
        __ = jwt.decode(cert_data, root)
    except Exception, e:
        print "Failed to verify root key signature on certificate: %s" % e
        sys.exit(1)

    # Check that our private key and public key halves match
    try:
        digest = hashlib.sha256(cert_data).digest()
        signature = priv.sign(digest, 'sha256')
        pub.verify(digest, signature, 'sha256')
    except Exception, e:
        print "Heap big trouble, Batman!  The keys do not appear to be a matched pair: %s" % e
        sys.exit(1)

    print "Looks good."
