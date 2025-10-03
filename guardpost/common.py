from collections.abc import Mapping
from typing import Mapping as MappingType, Optional
from typing import Sequence, Union

from .authorization import AuthorizationContext, Policy, Requirement


class AnonymousRequirement(Requirement):
    """Requires an anonymous user, or service."""

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if not identity or not identity.is_authenticated():
            context.succeed(self)


class AnonymousPolicy(Policy):
    """Policy that requires an anonymous user, or service."""

    def __init__(self, name: str = "anonymous"):
        super().__init__(name, AnonymousRequirement())


class AuthenticatedRequirement(Requirement):
    """
    Requires an authenticated user, or service. Meaning that an `identity` must be set
    in the authorization context.
    """

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if identity and identity.is_authenticated():
            context.succeed(self)


RequiredClaimsType = Union[MappingType[str, str], Sequence[str], str]


class ClaimsRequirement(Requirement):
    """Requires an identity with a claims: one or more, optionally with exact values."""

    __slots__ = ("required_claims",)

    def __init__(self, required_claims: RequiredClaimsType):
        if isinstance(required_claims, str):
            required_claims = [required_claims]
        self.required_claims = required_claims

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if not identity:
            context.fail("Missing identity")
            return

        if isinstance(self.required_claims, Mapping):
            if all(
                identity.has_claim_value(key, value)
                for key, value in self.required_claims.items()
            ):
                context.succeed(self)
        else:
            if all(identity.has_claim(name) for name in self.required_claims):
                context.succeed(self)


class RolesRequirement(Requirement):
    """
    Requires an identity with certain roles.
    Supports defining sufficient roles (any one is enough), and required roles (all
    must be present).
    """

    __slots__ = ("_roles", "_required_roles")

    def __init__(
        self,
        roles: Optional[Sequence[str]] = None,
        required_roles: Optional[Sequence[str]] = None,
    ):
        self._required_roles = list(required_roles) if required_roles else None
        self._roles = list(roles) if roles else None

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if not identity:
            context.fail("Missing identity")
            return

        if self._roles:
            if any(identity.has_role(name) for name in self._roles):
                context.succeed(self)

        if self._required_roles:
            if all(identity.has_role(name) for name in self._required_roles):
                context.succeed(self)
