[![Build](https://github.com/Neoteroi/guardpost/workflows/Build/badge.svg)](https://github.com/Neoteroi/guardpost/actions?query=workflow%3ABuild)
[![pypi](https://img.shields.io/pypi/v/neoteroi-auth.svg?color=blue)](https://pypi.org/project/neoteroi-auth/)
[![versions](https://img.shields.io/pypi/pyversions/neoteroi-auth.svg)](https://github.com/Neoteroi/guardpost)
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
pip install neoteroi-auth
```

To install with support for `JSON Web Tokens (JWTs)` validation:

```
pip install neoteroi-auth[jwt]
```

### Examples

For examples, refer to the [examples folder](./examples).

## If you have doubts about authentication vs authorization...
`Authentication` answers the question: _Who is the user who is initiating the
action?_, or more in general: _Who is the user, or what is the service, that is
initiating the action?_.

`Authorization` answers the question: _Is the user, or service, authorized to
do something?_.

Usually, to implement authorization, is necessary to have the context of the
entity that is executing the action.

## Usage in BlackSheep
`neoteroi-auth` is used in the second version of the
[BlackSheep](https://www.neoteroi.dev/blacksheep/) web framework, to implement
[authentication and authorization
strategies](https://www.neoteroi.dev/blacksheep/authentication/) for request
handlers.

To see how `neoteroi-auth` is used in `blacksheep` web framework, read:

* [Authentication](https://www.neoteroi.dev/blacksheep/authentication/)
* [Authorization](https://www.neoteroi.dev/blacksheep/authorization/)

# Documentation

Under construction. 🚧
