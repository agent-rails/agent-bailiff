from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

Platform = Literal["upstream", "gke", "eks"]
PLATFORMS: tuple[Platform, ...] = ("upstream", "gke", "eks")
VERSION_PATH = "/version"
GKE_VERSION_MARKER = "-gke."
ACCEPTED_INCOMPLETE: Mapping[Platform, frozenset[str]] = {
    "upstream": frozenset(),
    "gke": frozenset({"webhook authorizer does not support user rule resolution"}),
    "eks": frozenset(),
}


def parse_platform(value: object) -> Platform:
    if value not in PLATFORMS:
        raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}")
    return value


def check_version(platform: Platform, version: object) -> list[str]:
    git_version = version.get("gitVersion") if isinstance(version, dict) else None
    if not isinstance(git_version, str) or not git_version:
        return [f"{VERSION_PATH} returned no gitVersion"]
    on_gke = GKE_VERSION_MARKER in git_version
    if on_gke and platform != "gke":
        return [f"the cluster runs GKE ({git_version}) but the effector platform is {platform}"]
    if platform == "gke" and not on_gke:
        return [f"the effector platform is gke but the cluster runs {git_version}"]
    return []


def accepts_incomplete(platform: Platform, status: Mapping[str, Any]) -> bool:
    error = status.get("evaluationError")
    return status.get("incomplete") is True and isinstance(error, str) and error in ACCEPTED_INCOMPLETE[platform]
