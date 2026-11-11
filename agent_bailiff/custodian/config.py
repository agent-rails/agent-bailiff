from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class CustodianConfig:
    custodian_id: str
    decider_id: str
    decide_keys: Mapping[str, Ed25519PublicKey]
    docket_writer: str
    max_proof_age: int
    max_clearance_lifetime: int
    skew_seconds: int
    rate_limit: int
    rate_window: int

    def __post_init__(self) -> None:
        for name in ("custodian_id", "decider_id", "docket_writer"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str")
        if not isinstance(self.decide_keys, Mapping) or not self.decide_keys:
            raise ValueError("decide_keys must be a non-empty mapping of key ids to Ed25519 public keys")
        for kid, key in self.decide_keys.items():
            if not isinstance(kid, str) or not kid or not isinstance(key, Ed25519PublicKey):
                raise ValueError("decide_keys must map non-empty str key ids to Ed25519 public keys")
        object.__setattr__(self, "decide_keys", MappingProxyType(dict(self.decide_keys)))
        for name in ("max_proof_age", "max_clearance_lifetime", "rate_limit", "rate_window"):
            _require_int(name, getattr(self, name), minimum=1)
        _require_int("skew_seconds", self.skew_seconds, minimum=0)
        if self.max_clearance_lifetime > self.max_proof_age:
            raise ValueError("max_clearance_lifetime must not exceed max_proof_age")


def _require_int(name: str, value: object, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer of at least {minimum}")
