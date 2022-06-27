
import requests
import json 


#Create client key pair
'''
>>> key = jwk.JWK.generate(kty='EC', crv='P-256')
>>> print (key.export(as_dict=True))
'''
client_key_dict = {'kty': 'EC', 'crv': 'P-256', 'x': 'z30WuxpsPow8KpH0N93vW24nA0HD48_MluqgdEUvtU4', 'y': 'VcKco12BZFPu5HU2LBLotTD9NitdlNxnBLngD-eTapM'} 

#Generate RAR
rar = {
    "type":"pop-jwk",
    "jwk":client_key_dict
}


# Prepare the request
print(rar)
data    = {"grant_type":"client_credentials", "authorization_details":json.dumps(rar)}
issuer  =  "http://localhost:5000/oauth2/token/1" 
auth    =  ("wallet","qwerty") 
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
response  = requests.post(issuer, auth=auth, headers = headers, data=data)
print(response.text)