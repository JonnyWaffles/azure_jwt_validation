class TokenValidationException(Exception):
    """Base Exception for Token Validation errors"""
    pass


class InvalidAuthorizationToken(TokenValidationException):
    """Raised when the configuration is fine, but token validation fails."""
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)
