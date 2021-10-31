class AuthException(Exception):
    """Base class for all exception risen by the library."""


class UnsupportedFeatureError(AuthException):
    """Exception risen for unsupported features."""
