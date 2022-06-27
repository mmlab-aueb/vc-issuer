
import requests
import json 


#Create client key pair
'''
>>> key = jwk.JWK.generate(kty='EC', crv='P-256')
>>> print (key.export(as_dict=True))
'''
client_key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'vnTP8BkkMuw99RsdN0Vw0f--hUqKWsU9rTnb8mV03hg', 'd': 'brF6hpvy4t6Puc_JC01B_W4V9rj1pwa8IHbgMUTWrMY'}
#Generate RAR
rar = {
    "type":"pop-did",
    "did":"did:self:" + client_key_dict['x']
}


# Prepare the request
print(rar)
data    = {"grant_type":"client_credentials", "authorization_details":json.dumps(rar)}
issuer  =  "http://localhost:5000/oauth2/token/1" 
auth    =  ("wallet","qwerty") 
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
response  = requests.post(issuer, auth=auth, headers = headers, data=data)
print(response.text)