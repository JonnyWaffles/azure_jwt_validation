# Azure JWT Validation
## Purpose
Easy to use package to validate JWT tokens provided by Azure. You would
think this exists somewhere already but I could not find anything in
the azure ADAL library.

The challenge was transforming the public JWK to a PEM format [PyJWT](https://github.com/jpadilla/pyjwt) could use to validate.
Thankfully, I eventually found this fantastic
[post](https://robertoprevato.github.io/Validating-JWT-Bearer-tokens-from-Azure-AD-in-Python/)
by Roberto Prevato and implemented it in this package.

It's possible I just missed something. So, if
a better solution is discovered please let me know and I will blow this away.

## Usage
Simple usage, provided you already have a jwk
```python
# Given a token as str and JWK as dict
from azure_jwt_validation import validate_jwt

obj = validate_jwt(token, jwk)
```
Or automatically get the keys
```python
# Create a validator capable of refreshing its public keys
from azure_jwt_validation import JWTTokenValidator

validator = JWTTokenValidator(
    ad_tenant='yourtenant.onmicrosoft.com',
    application_id='yourappguid',
    audiences=['probablyyourappguid']
)
# Call these functions to refresh the keys from either the disk
# or from Azure (default)
validator.load_ms_public_keys()
validator.load_open_id_config()

obj = validator.validate_jwt(token)
```
By default calling the load functions will make a request
to retrieve the config and public keys and save both
to json files in the package.
Pass ``force_refresh=False`` To prevent the request and
fall back on these files.

## TODO
- Originally, only wrote the package to handle openid connect. Consider looking at validating other tokens.

