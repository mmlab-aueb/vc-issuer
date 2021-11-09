import requests
import json 



headers = {'Authorization':'DPoP ' + token, 'Accept': 'application/json', 'dpop':dpop}
response  = requests.get("http://localhost:9000/secure/jwt-vc-dpop", headers = headers)
print(response.text)

'''
curl -i -u ReAvJAChSk24Dj6ijG6vSh7T:yCh4B7dloXRoOdTzuIY1050L -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" https://as.controlthings.gr/oauth2/token/nikosft
curl --insecure -i -u yeVI8A9pTdwI-4yuTSmRIJ3i:AVmgZb3JrnKkWoEUiFFDmXin -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" https://localhost:5001/oauth2/token/nikosft
'''