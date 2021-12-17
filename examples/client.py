
import requests
import json 
from jwcrypto import jwt, jwk

#Create client key pair
'''
>>> key = jwk.JWK.generate(kty='EC', crv='P-256')
>>> print (key.export(as_dict=True))
'''
client_key_dict = {'kty': 'EC', 'crv': 'P-256', 'x': 'z30WuxpsPow8KpH0N93vW24nA0HD48_MluqgdEUvtU4', 'y': 'VcKco12BZFPu5HU2LBLotTD9NitdlNxnBLngD-eTapM', 'd': 'UCe_iiyGTQf13KyLPhLgjVCT3gSx4APgNSbS7uyLxN8'} 
client_key = jwk.JWK.from_json(json.dumps(client_key_dict))

#Generate DPoP
dpop_header = {
    "typ": "dpop+jwt",
    "alg": "ES256",
    "jwk": client_key.export_public(as_dict=True)
}
dpop_claims = {
    "jti": "-BwC3ESc6acc2lTc",
    "htm": "POST",
    "htu": "https://issuer.mmlab.edu.gr",
    "iat": 1562262616
}
dpop = jwt.JWT(header=dpop_header, claims=dpop_claims)
dpop.make_signed_token(client_key)


# Prepare the request
data    = "grant_type=client_credentials"
issuer  =  "http://localhost:5000/oauth2/issue/mmlab" 
auth    =  ("wallet","qwerty") 
headers = {'Content-Type': 'application/x-www-form-urlencoded', 'DPoP':dpop.serialize()}
response  = requests.post(issuer, auth=auth, headers = headers, data=data)
print(response.text)