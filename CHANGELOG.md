# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2022-12-xx :star:
- Renames the library to `neoteroi-auth`.
- Adopts PEP 420 and renames the main namespace from `guardpost` to `neoteroi.auth`
- Adds built-in support for dependency injection, using the new `ContainerProtocol`
  in `neoteroi-di` (new version of `rodi`).
- Removes the synchronous code API, maintaining only the asynchronous code API
  for `AuthenticationStrategy.authenticate` and `AuthorizationStrategy.authorize`.
- Replaces `setup.py` with `pyproject.toml`.
- Reduces imports verbosity.
- Improves the `identity_getter` code API.
- Corrects `Identity.__getitem__` to raise `KeyError` if a claim is missing.

## [0.1.0] - 2022-11-06 :snake:
- Workflow maintenance.

## [0.0.9] - 2021-11-14 :swan:
- Adds `sub`, `access_token`, and `refresh_token` properties to the `Identity`.
  class
- Adds `py.typed` file.

## [0.0.8] - 2021-10-31 :shield:
- Adds classes to handle `JWT`s validation, but only for `RSA` keys.
- Fixes issue (wrong arrangement in test) #5.
- Includes `Python 3.10` in the CI/CD matrix.
- Enforces `black` and `isort` in the CI pipeline.

## [0.0.7] - 2021-01-31 :grapes:
- Corrects a bug in the `Policy` class (#2).
- Changes the type annotation of `Identity` claims (#3).

## [0.0.6] - 2020-12-12 :octocat:
- Completely migrates to GitHub Workflows.
- Improves build to test Python 3.6 and 3.9.
- Adds a changelog.
- Improves badges.
- Improves code quality using `flake8` and `black`.
