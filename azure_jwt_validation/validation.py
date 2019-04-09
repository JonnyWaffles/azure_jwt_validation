import base64
from typing import List, Sequence

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from azure_jwt_validation import TokenValidationException, InvalidAuthorizationToken
from azure_jwt_validation import config


RequestException = requests.exceptions.RequestException


def ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key


def decode_value(val):
    decoded = base64.urlsafe_b64decode(ensure_bytes(val) + b'==')
    return int.from_bytes(decoded, 'big')


def rsa_pem_from_jwk(jwk):
    """Creates a pem from a jwk."""
    return RSAPublicNumbers(
        n=decode_value(jwk['n']),
        e=decode_value(jwk['e'])
    ).public_key(default_backend()).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def validate_jwt(token: str, jwk: dict, **kwargs):
    """Validate a token.

    #. Convert the public key to a valid pem
    #. Decode and validate the token.

    Args:
        token: The jwt token
        jwk: The json web key to validate against
    """
    public_pem = rsa_pem_from_jwk(jwk)
    kwargs.setdefault('algorithms', ['RS256'])
    return jwt.decode(token,
                      public_pem,
                      verify=True,
                      **kwargs)


class JWTTokenValidator:
    def __init__(self,
                 ad_tenant,
                 application_id,
                 audiences=None,
                 ms_signing_key_url='https://login.microsoftonline.com/common/discovery/keys'):
        """Validates tokens by checking the signature against the public key.
        Either provide the settings, or
        call the load functions to either get the config from the package resource json, or
        pull it down from Azure.

        Args:
            ad_tenant: Ad tenant name example testname.onmicrosoft.com
            application_id: The application id the tokens are issued to, ie your app.
            audiences: A list of audience values, generally the same as the application_id
            ms_signing_key_url: Url for Azure's public keys
        """
        self.ad_tenant = ad_tenant
        self.application_id = application_id
        if isinstance(audiences, str) or not isinstance(audiences, Sequence):
            raise AttributeError('audiences must be a list of audience names.')
        self.audiences = audiences
        self.ms_signing_key_url = ms_signing_key_url
        self.openid_config = None
        self.ms_public_keys = None
        self.issuer = None

    def validate_jwt(self, token: str):
        """Validates the given token."""
        kwargs = {}
        if self.issuer:
            kwargs['issuer'] = self.issuer
        if self.audiences:
            kwargs['audiences'] = self.audiences
        jwk = self.get_jwk(token)
        return validate_jwt(token, jwk, **kwargs)

    def load_open_id_config(self, force_refresh=True, refresh_on_missing=True):
        """Attempts to load the openid config from the package resource file,
        or loads from Azure. Additionally, sets the :attr:`issuer` attribute
        from the config.

        .. note::

            The package resource file openid_config.json exists to cache the last
            loaded config so as to minimize requests. If multiple :class:`JWTTokenValidator` instances exist,
            always force a refresh.

        Args:
            force_refresh: Always the config from Azure
            refresh_on_missing: Only refresh from Azure if the config file is missing.

        Raises:
            :exc:`TokenValidationException`: When an issuer is not in the config or set on the instance.
        """
        self.openid_config = self._load_open_id_config(force_refresh, refresh_on_missing)
        try:
            self.issuer = self.openid_config['issuer']
        except KeyError:
            if not self.issuer:
                raise TokenValidationException('Could not obtain valid issuer from open id configuration.')
            pass

    def load_ms_public_keys(self, force_refresh=True, refresh_on_missing=True):
        """Similar to :meth:`load_open_id_config` only for the public keys.

        Sets the keys on the self.ms_public_keys attribute.
        """
        self.ms_public_keys = self._load_ms_public_keys(force_refresh, refresh_on_missing)

    @staticmethod
    def get_kid(token):
        """Returns the token's kid value."""
        headers = jwt.get_unverified_header(token)
        if not headers:
            raise InvalidAuthorizationToken('missing headers')
        try:
            return headers['kid']
        except KeyError:
            raise InvalidAuthorizationToken('missing kid')

    def get_jwk(self, token: str):
        """Gets the public jwk the token was signed with or throws if no public key is found."""
        kid = self.get_kid(token)
        for key in self.ms_public_keys:
            if key['kid'] == kid:
                return key
        raise InvalidAuthorizationToken('kid not recognized')

    def _load_open_id_config(self, force_refresh, refresh_on_missing):
        if not force_refresh:
            try:
                return config.get_cached_open_id_config()
            except TokenValidationException:
                if not refresh_on_missing:
                    raise
        return config.update_open_id_config(self.ad_tenant)

    def _load_ms_public_keys(self, force_refresh, refresh_on_missing):
        if not force_refresh:
            try:
                return config.get_cached_public_keys()
            except TokenValidationException:
                if not refresh_on_missing:
                    raise
        return config.update_current_microsoft_public_keys_file(self.ms_signing_key_url)
