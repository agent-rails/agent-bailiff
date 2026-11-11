from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_guard.policy import Policy
from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import sha256_b64u
from agent_warrant.scope import validate_entry


@dataclass(frozen=True)
class TargetBinding:
    tenant: str
    tool: str
    resource: str
    credential_id: str
    target: str
    custodian: str

    def __post_init__(self) -> None:
        for name in ("tenant", "credential_id", "target", "custodian"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str")
        problem = validate_entry(self.tool)
        if problem or "*" in self.tool:
            raise ValueError(f"tool must be a concrete id: {problem or 'no wildcards'}")
        problem = validate_entry(self.resource)
        if problem:
            raise ValueError(f"resource: {problem}")

    def matches(self, tenant: str, tool: str, resource: str) -> bool:
        if (self.tenant, self.tool) != (tenant, tool):
            return False
        if self.resource.endswith("*"):
            return resource.startswith(self.resource[:-1])
        return self.resource == resource


@dataclass(frozen=True)
class PolicyRef:
    policy: Policy
    policy_id: str
    version: str
    digest: str

    @classmethod
    def from_dict(cls, policy_id: str, version: str, data: dict[str, Any]) -> PolicyRef:
        if not isinstance(policy_id, str) or not policy_id or not isinstance(version, str) or not version:
            raise ValueError("policy_id and version must be non-empty str")
        return cls(Policy.from_dict(data), policy_id, version, sha256_b64u(canonicalize(data)))


@dataclass(frozen=True)
class DeciderConfig:
    decider_id: str
    kid: str
    custodian_ids: frozenset[str]
    max_proof_age: int
    bindings: tuple[TargetBinding, ...]
    docket_writer: str

    def __post_init__(self) -> None:
        for name in ("decider_id", "kid", "docket_writer"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str")
        object.__setattr__(self, "custodian_ids", frozenset(self.custodian_ids))
        if not self.custodian_ids or not all(isinstance(item, str) and item for item in self.custodian_ids):
            raise ValueError("custodian_ids must be a non-empty set of non-empty str")
        age = self.max_proof_age
        if isinstance(age, bool) or not isinstance(age, int) or age <= 0:
            raise ValueError("max_proof_age must be a positive integer")
        object.__setattr__(self, "bindings", tuple(self.bindings))
        if not all(isinstance(item, TargetBinding) for item in self.bindings):
            raise TypeError("bindings must be TargetBinding records")
        unknown = sorted({item.custodian for item in self.bindings} - self.custodian_ids)
        if unknown:
            raise ValueError(f"bindings name a custodian outside custodian_ids: {', '.join(unknown)}")

    def binding(self, tenant: str, tool: str, resource: str) -> TargetBinding | None:
        return next((item for item in self.bindings if item.matches(tenant, tool, resource)), None)
