from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


DID_PATTERN = re.compile(
    r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$"
)


@dataclass(frozen=True)
class DIDInfo:
    did: str
    fingerprint: str
    namespace: str
    key: str

    @property
    def profile_url(self) -> str:
        return (
            f"https://technocore.chat/kv/"
            f"{self.namespace}/{self.key}"
        )


def get_did_info(did: str) -> DIDInfo:
    """
    Generate Technocore profile information from a did:key.
    """
    if not isinstance(did, str) or not DID_PATTERN.fullmatch(did):
        raise ValueError("invalid did:key")

    fingerprint = hashlib.sha256(
        did.encode("utf-8")
    ).hexdigest()[:16]

    namespace = f"did-{fingerprint[:2]}"
    key = fingerprint[2:]

    return DIDInfo(
        did=did,
        fingerprint=fingerprint,
        namespace=namespace,
        key=key,
    )
