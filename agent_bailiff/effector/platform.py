from __future__ import annotations

from typing import Literal

Platform = Literal["upstream", "gke", "eks"]
PLATFORMS: tuple[Platform, ...] = ("upstream", "gke", "eks")
VERSION_PATH = "/version"
GKE_VERSION_MARKER = "-gke."


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
