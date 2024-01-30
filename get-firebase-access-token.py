import time
import json
import jwt
import requests

# Set how long this token will be valid in seconds
expires_in = 3600	# Expires in 1 hour

def create_signed_jwt():
    '''
    Create a Signed JWT from the data in the service account Json credentials file
    This Signed JWT will later be exchanged for an Access Token
    '''

    issued = int(time.time())
    expires = issued + expires_in	# expires_in is in seconds

    # Note: this token expires and cannot be refreshed. The token must be recreated

    # JWT Headers
    additional_headers = {
            'kid': <private_key_id>,
            "alg": "RS256", # Google uses SHA256withRSA
            "typ": "JWT"
    }

    # JWT Payload
    payload = {
        "iss": <client_email>,		# Issuer claim
        "sub": <client_email>,		# Issuer claim
        "aud": "https://www.googleapis.com/oauth2/v4/token",	# Audience claim
        "iat": issued,		# Issued At claim
        "exp": expires,		# Expire time
        "scope": "https://www.googleapis.com/auth/firebase.messaging"		# Permissions
    }

    # Encode the headers and payload and sign creating a Signed JWT (JWS)
    sig = jwt.encode(payload, <private_key>, algorithm="RS256", headers=additional_headers)

    return sig

def exchangeJwtForAccessToken(signed_jwt):
    '''
    This function takes a Signed JWT and exchanges it for a Google OAuth Access Token
    '''

    auth_url = "https://oauth2.googleapis.com/token"

    params = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt
    }

    r = requests.post(auth_url, data=params)

    if r.ok:
        return(r.json()['access_token'], '')

    return None, r.text


if __name__ == '__main__':

    s_jwt = create_signed_jwt()

    token, err = exchangeJwtForAccessToken(s_jwt)
    
    print(token)

    if token is None:
        print('Error:', err)
        exit(1)
