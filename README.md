[![Build](https://github.com/Neoteroi/guardpost/workflows/Build/badge.svg)](https://github.com/Neoteroi/guardpost/actions?query=workflow%3ABuild)
[![pypi](https://img.shields.io/pypi/v/guardpost.svg?color=blue)](https://pypi.org/project/guardpost/)
[![versions](https://img.shields.io/pypi/pyversions/guardpost.svg)](https://github.com/Neoteroi/guardpost)
[![license](https://img.shields.io/github/license/Neoteroi/guardpost.svg)](https://github.com/Neoteroi/guardpost/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/Neoteroi/guardpost/branch/main/graph/badge.svg?token=sBKZG2D1bZ)](https://codecov.io/gh/Neoteroi/guardpost)

# Authentication and authorization framework for Python apps
Basic framework to handle authentication and authorization in asynchronous
Python applications.

**Features:**

- strategy to implement authentication (who or what is using a service?)
- strategy to implement authorization (is the acting identity authorized to do a certain action?)
- support for dependency injection for classes handling authentication and
  authorization requirements
- built-in support for JSON Web Tokens (JWTs) authentication

This library is freely inspired by [authorization in ASP.NET
Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-2.2);
although its implementation is extremely different.

## Installation

```bash
pip install guardpost
```

To install with support for `JSON Web Tokens (JWTs)` validation:

```
pip install guardpost[jwt]
```

### Examples

For examples, refer to the [examples folder](./examples).

## Functions to validate JWTs

GuardPost includes functions to validate JSON Web Tokens (JWTs) and handle
JSON Web Keys Sets (JWKS).

The built-in validator class can retrieve automatically JWKS from identity providers
and handle automatically caching and keys rotation. Caching is useful to not incur in
useless performance fees (e.g. downloading JWKS at each web request), and keys rotation
is important because identity providers can periodically change the keys they use to
sign JWTs.

To use these features, install to include additional dependencies:

```bash
pip install guardpost[jwt]
```

The following example shows how to use guardpost to validate tokens:

```python
import asyncio
from guardpost.jwts import JWTValidator


async def main():
    validator = JWTValidator(
        authority="YOUR_AUTHORITY",
        valid_issuers=["YOUR_ISSUER_VALUE"],
        valid_audiences=["YOUR_AUDIENCE"],
    )

    # keys are fetched when necessary
    data = await validator.validate_jwt("YOUR_TOKEN")

    print(data)


asyncio.run(main())
```

An example value for `authority`, to validate access tokens issued by
Azure Active Directory could be: `https://sts.windows.net/YOUR_TENANT_ID/`.

GuardPost is used in BlackSheep and has been tested with:

- Auth0
- Azure Active Directory
- Azure Active Directory B2C
- Okta

## If you have doubts about authentication vs authorization...
`Authentication` answers the question: _Who is the user who is initiating the
action?_, or more in general: _Who is the user, or what is the service, that is
initiating the action?_.

`Authorization` answers the question: _Is the user, or service, authorized to
do something?_.

Usually, to implement authorization, is necessary to have the context of the
entity that is executing the action.

## Usage in BlackSheep
`guardpost` is used in the [BlackSheep](https://www.neoteroi.dev/blacksheep/)
web framework, to implement [authentication and authorization
strategies](https://www.neoteroi.dev/blacksheep/authentication/) for request
handlers.

To see how `guardpost` is used in `blacksheep` web framework, read:

* [Authentication](https://www.neoteroi.dev/blacksheep/authentication/)
* [Authorization](https://www.neoteroi.dev/blacksheep/authorization/)

# Documentation

Under construction. 🚧
