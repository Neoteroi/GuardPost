class AuthException(Exception):
    """Base class for exceptions related to the library itself."""


class UnsupportedFeatureError(AuthException):
    """Exception raised for unsupported features."""


class InvalidCredentialsError(AuthException):
    """
    Exception to be raised when invalid credentials are provided. This exception is
    handled to implement rate limiting and provide protection against brute-force
    attacks.
    """

    def __init__(self, client_ip: str, key: str = "") -> None:
        super().__init__(f"Invalid credentials were received from {client_ip}.")

        if not client_ip:
            raise ValueError("Missing or empty client IP")

        self._client_ip = client_ip
        self._key = key or client_ip

    @property
    def client_ip(self) -> str:
        return self._client_ip

    @property
    def key(self) -> str:
        return self._key

    @key.setter
    def key(self, value: str):
        self._key = value
