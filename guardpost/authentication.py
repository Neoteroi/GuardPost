from typing import Dict, Union, Optional


ClaimValueType = Union[bool, str, Dict]


class Identity:

    def __init__(self, claims: Dict[str, ClaimValueType], authentication_mode: Optional[str] = None):
        self.claims = claims or {}
        self.authentication_mode = authentication_mode

    def is_authenticated(self):
        return bool(self.authentication_mode)

    def __getitem__(self, item):
        return self.claims.get(item)

    def has_claim(self, name: str) -> bool:
        return name in self.claims

    def has_claim_value(self, name: str, value: str) -> bool:
        return self.claims.get(name) == value


class User(Identity):

    @property
    def id(self):
        return self['id']

    @property
    def name(self):
        return self['name']

    @property
    def email(self):
        return self['email']

