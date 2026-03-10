<!-- generated file, to update use: python examples-summary.py -->

# Examples

## example-01.py

This example illustrates a basic use of the authentication strategy, using a single
authentication handler.


## example-02.py

This example illustrates a basic use of the authentication strategy, using more than
one way to obtain the user's identity.


## example-03.py

This example illustrates a basic use of the authentication strategy, showing how
authentication handlers can be grouped by authentication schemes.


## example-04.py

This example illustrates how dependency injection can be used for authentication
handlers.


## example-05.py

This example illustrates a basic use of an authorization strategy.


## example-06.py

This example illustrates how to use an authorization strategy having more than one set
of criteria to handle authorization, and how to decorate methods so they require
authorization.


## example-07.py

This example illustrates a basic use of an authorization strategy, with support for
dependency injection for authorization requirements.


## example-08.py

This example illustrates how to validate JWTs signed with RSA keys (RS256),
using an in-memory JWKS built from a generated RSA key pair.


## example-09.py

This example illustrates how to validate JWTs signed with EC keys (ES256, ES384,
ES512), using an in-memory JWKS built from generated EC key pairs.


## example-10.py

This example illustrates how to validate JWTs signed with a symmetric secret key
(HMAC), using the SymmetricJWTValidator with HS256, HS384, and HS512 algorithms.
