from http.client import HTTPResponse


class AuthException(Exception):
    """Base class for all exception risen by the library."""


class FailedRequestError(AuthException):
    def __init__(self, response: HTTPResponse) -> None:
        super().__init__(
            f"Response status does not indicate success: {response.status}"
        )
        self.status = response.status
        self.data = response.read()
