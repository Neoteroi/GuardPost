[![Build](https://github.com/Neoteroi/guardpost/workflows/Build/badge.svg)](https://github.com/Neoteroi/guardpost/actions?query=workflow%3ABuild)
[![pypi](https://img.shields.io/pypi/v/guardpost.svg?color=blue)](https://pypi.org/project/guardpost/)
[![versions](https://img.shields.io/pypi/pyversions/guardpost.svg)](https://github.com/Neoteroi/guardpost)
[![license](https://img.shields.io/github/license/Neoteroi/guardpost.svg)](https://github.com/Neoteroi/guardpost/blob/master/LICENSE)
[![codecov](https://codecov.io/gh/Neoteroi/guardpost/branch/master/graph/badge.svg?token=sBKZG2D1bZ)](https://codecov.io/gh/Neoteroi/guardpost)

# GuardPost
GuardPost provides a basic framework to handle authentication and authorization
in any kind of Python application.

```bash
pip install guardpost
```

This library is freely inspired by [authorization in ASP.NET
Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-2.2);
although its implementation is extremely different.

Notable differences are:
1. GuardPost is abstracted from the code that executes it, so it's not bound to
   the context of a web framework.
1. GuardPost implements both classes for use with synchronous code (not
   necessarily I/O bound), and classes using `async/await` syntax (optimized
   for authentication and authorization rules that involve I/O bound operations
   such as web requests and communications with databases).
1. GuardPost leverages Python function decorators for the authorization part,
   so any function can be wrapped to be executed after handling authorization.
1. The code API is simpler.

## More documentation and examples
For documentation and
[examples](https://github.com/RobertoPrevato/GuardPost/wiki/Examples), refer to
the project [Wiki](https://github.com/RobertoPrevato/GuardPost/wiki).

To see how `guardpost` is used in `blacksheep` web framework, read the
documentation here:

* [Authentication](https://www.neoteroi.dev/blacksheep/authentication/)
* [Authorization](https://www.neoteroi.dev/blacksheep/authorization/)

## Both for async/await and synchronous code
GuardPost can be used both with async/await code and with synchronous code,
according to use cases and users' preference.

## If you have doubts about authentication vs authorization...
`Authentication` answers the question: _Who is the user who is executing the
action?_, or more in general: _Who is the user, or what is the service, that is
executing the action?_.

`Authorization` answers the question: _Is the user, or service, authorized to
do something?_.

Usually, to implement authorization, is necessary to have the context of the
entity that is executing the action. Anyway, the two things are logically
separated and GuardPost is designed to keep them separate.
